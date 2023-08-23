function Invoke-Action
{

    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Alias("c")]
        [String[]]
        $CollectionMethod = [String[]]@('Default'),

        [Alias("d")]
        [String]
        $Domain,
        
        [Alias("s")]
        [Switch]
        $SearchForest,

        [Switch]
        $Stealth,

        [String]
        $LdapFilter,

        [String]
        $DistinguishedName,

        [String]
        $ComputerFile,

        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $OutputDirectory = $( Get-Location ),

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputPrefix,

        [String]
        $CacheName,

        [Switch]
        $MemCache,

        [Switch]
        $RebuildCache,

        [Switch]
        $RandomFilenames,

        [String]
        $ZipFilename,
        
        [Switch]
        $NoZip,
        
        [String]
        $ZipPassword,
        
        [Switch]
        $TrackComputerCalls,
        
        [Switch]
        $PrettyPrint,

        [String]
        $LdapUsername,

        [String]
        $LdapPassword,

        [string]
        $DomainController,

        [ValidateRange(0, 65535)]
        [Int]
        $LdapPort,

        [Switch]
        $SecureLdap,
        
        [Switch]
        $DisableCertVerification,

        [Switch]
        $DisableSigning,

        [Switch]
        $SkipPortCheck,

        [ValidateRange(50, 5000)]
        [Int]
        $PortCheckTimeout = 500,

        [Switch]
        $SkipPasswordCheck,

        [Switch]
        $ExcludeDCs,

        [Int]
        $Throttle,

        [ValidateRange(0, 100)]
        [Int]
        $Jitter,

        [Int]
        $Threads,

        [Switch]
        $SkipRegistryLoggedOn,

        [String]
        $OverrideUsername,

        [String]
        $RealDNSName,

        [Switch]
        $CollectAllProperties,

        [Switch]
        $Loop,

        [String]
        $LoopDuration,

        [String]
        $LoopInterval,

        [ValidateRange(500, 60000)]
        [Int]
        $StatusInterval,
        
        [Alias("v")]
        [ValidateRange(0, 5)]
        [Int]
        $Verbosity,

        [Alias("h")]
        [Switch]
        $Help,

        [Switch]
        $Version
    )

    $vars = New-Object System.Collections.Generic.List[System.Object]

    if ($CollectionMethod)
    {
        $vars.Add("--CollectionMethods");
        foreach ($cmethod in $CollectionMethod)
        {
            $vars.Add($cmethod);
        }
    }

    if ($Domain)
    {
        $vars.Add("--Domain");
        $vars.Add($Domain);
    }
    
    if ($SearchForest)
    {
        $vars.Add("--SearchForest")    
    }

    if ($Stealth)
    {
        $vars.Add("--Stealth")
    }

    if ($LdapFilter)
    {
        $vars.Add("--LdapFilter");
        $vars.Add($LdapFilter);
    }

    if ($DistinguishedName)
    {
        $vars.Add("--DistinguishedName")
        $vars.Add($DistinguishedName)
    }
    
    if ($ComputerFile)
    {
        $vars.Add("--ComputerFile");
        $vars.Add($ComputerFile);
    }

    if ($OutputDirectory)
    {
        $vars.Add("--OutputDirectory");
        $vars.Add($OutputDirectory);
    }

    if ($OutputPrefix)
    {
        $vars.Add("--OutputPrefix");
        $vars.Add($OutputPrefix);
    }

    if ($CacheName)
    {
        $vars.Add("--CacheName");
        $vars.Add($CacheName);
    }

    if ($NoSaveCache)
    {
        $vars.Add("--MemCache");
    }

    if ($RebuildCache)
    {
        $vars.Add("--RebuildCache");
    }

    if ($RandomFilenames)
    {
        $vars.Add("--RandomFilenames");
    }

    if ($ZipFileName)
    {
        $vars.Add("--ZipFileName");
        $vars.Add($ZipFileName);
    }

    if ($NoZip)
    {
        $vars.Add("--NoZip");
    }

    if ($ZipPassword)
    {
        $vars.Add("--ZipPassword");
        $vars.Add($ZipPassword)
    }

    if ($TrackComputerCalls)
    {
        $vars.Add("--TrackComputerCalls")
    }

    if ($PrettyPrint)
    {
        $vars.Add("--PrettyPrint");
    }

    if ($LdapUsername)
    {
        $vars.Add("--LdapUsername");
        $vars.Add($LdapUsername);
    }

    if ($LdapPassword)
    {
        $vars.Add("--LdapPassword");
        $vars.Add($LdapPassword);
    }

    if ($DomainController)
    {
        $vars.Add("--DomainController");
        $vars.Add($DomainController);
    }
    
    if ($LdapPort)
    {
        $vars.Add("--LdapPort");
        $vars.Add($LdapPort);
    }
    
    if ($SecureLdap)
    {
        $vars.Add("--SecureLdap");
    }
    
    if ($DisableCertVerification) 
    {
        $vars.Add("--DisableCertVerification")    
    }

    if ($DisableSigning)
    {
        $vars.Add("--DisableSigning");
    }

    if ($SkipPortCheck)
    {
        $vars.Add("--SkipPortCheck");
    }

    if ($PortCheckTimeout)
    {
        $vars.Add("--PortCheckTimeout")
        $vars.Add($PortCheckTimeout)
    }

    if ($SkipPasswordCheck)
    {
        $vars.Add("--SkipPasswordCheck");
    }

    if ($ExcludeDCs)
    {
        $vars.Add("--ExcludeDCs")
    }

    if ($Throttle)
    {
        $vars.Add("--Throttle");
        $vars.Add($Throttle);
    }

    if ($Jitter -gt 0)
    {
        $vars.Add("--Jitter");
        $vars.Add($Jitter);
    }
    
    if ($Threads)
    {
        $vars.Add("--Threads")
        $vars.Add($Threads)
    }

    if ($SkipRegistryLoggedOn)
    {
        $vars.Add("--SkipRegistryLoggedOn")
    }

    if ($OverrideUserName)
    {
        $vars.Add("--OverrideUserName")
        $vars.Add($OverrideUsername)
    }
    
    if ($RealDNSName)
    {
        $vars.Add("--RealDNSName")
        $vars.Add($RealDNSName)
    }

    if ($CollectAllProperties)
    {
        $vars.Add("--CollectAllProperties")
    }

    if ($Loop)
    {
        $vars.Add("--Loop")
    }

    if ($LoopDuration)
    {
        $vars.Add("--LoopDuration")
        $vars.Add($LoopDuration)
    }

    if ($LoopInterval)
    {
        $vars.Add("--LoopInterval")
        $vars.Add($LoopInterval)
    }

    if ($StatusInterval)
    {
        $vars.Add("--StatusInterval")
        $vars.Add($StatusInterval)
    }

    if ($Verbosity)
    {
        $vars.Add("-v");
        $vars.Add($Verbosity);
    }    

    if ($Help)
    {
        $vars.clear()
        $vars.Add("--Help");
    }

    if ($Version)
    {
        $vars.clear();
        $vars.Add("--Version");
    }

    $passed = [string[]]$vars.ToArray()


	$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
	$UncompressedFileBytes = New-Object Byte[](908288)
	$DeflatedStream.Read($UncompressedFileBytes, 0, 908288) | Out-Null
	$Assembly = [Reflection.Assembly]::Load($UncompressedFileBytes)
	$BindingFlags = [Reflection.BindingFlags] "Public,Static"
	$a = @()
	$Assembly.GetType("Costura.AssemblyLoader", $false).GetMethod("Attach", $BindingFlags).Invoke($Null, @())
	$Assembly.GetType("Sharphound.Program").GetMethod("InvokeSharpHound").Invoke($Null, @(,$passed))
}