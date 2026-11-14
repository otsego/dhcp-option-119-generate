#Requires -Version 5.1
# Dependency-free CLI tests. Run from any directory with Windows PowerShell or pwsh.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$generator = Join-Path (Split-Path -Parent $PSScriptRoot) 'dhcp-option-119-generate.ps1'
$runtime = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('option119-tests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
$runner = Join-Path $temporary 'run-case.ps1'
$fixture = Join-Path $temporary 'case.clixml'
@'
param([string] $Generator, [string] $Fixture)
$parameters = Import-Clixml -LiteralPath $Fixture
& $Generator @parameters
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $runner -Encoding Ascii
$script:passed = 0

function Assert-Equal {
    param($Actual, $Expected, [string] $Message)
    if ($Actual -cne $Expected) {
        throw ("{0}: expected '{1}', received '{2}'" -f $Message, $Expected, $Actual)
    }
}

function Invoke-Generator {
    param([hashtable] $Parameters)
    $Parameters | Export-Clixml -LiteralPath $fixture
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $runtime
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" "{1}" "{2}"' -f $runner, $generator, $fixture
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject] @{
            ExitCode = $process.ExitCode
            Stdout = $stdout.GetAwaiter().GetResult()
            Stderr = $stderr.GetAwaiter().GetResult()
        }
    }
    finally { $process.Dispose() }
}

function Read-SearchList {
    param([byte[]] $Bytes)
    $offset = 0
    while ($offset -lt $Bytes.Length) {
        $labels = New-Object 'System.Collections.Generic.List[string]'
        $cursor = $offset
        $consumed = -1
        $visited = New-Object 'System.Collections.Generic.HashSet[int]'
        while ($true) {
            if ($cursor -ge $Bytes.Length -or -not $visited.Add($cursor)) {
                throw 'DNS decoder: loop or out-of-bounds name'
            }
            $length = [int] $Bytes[$cursor]
            if (($length -band 0xC0) -eq 0xC0) {
                if ($cursor + 1 -ge $Bytes.Length) { throw 'DNS decoder: truncated pointer' }
                $target = (($length -band 0x3F) -shl 8) -bor $Bytes[$cursor + 1]
                if ($target -ge $cursor) { throw 'DNS decoder: non-backward pointer' }
                if ($consumed -eq -1) { $consumed = $cursor + 2 }
                $cursor = $target
            }
            elseif ($length -eq 0) {
                if ($consumed -eq -1) { $offset = $cursor + 1 } else { $offset = $consumed }
                break
            }
            elseif ($length -le 63 -and $cursor + 1 + $length -le $Bytes.Length) {
                $labels.Add([System.Text.Encoding]::ASCII.GetString($Bytes, $cursor + 1, $length))
                $cursor += 1 + $length
            }
            else { throw 'DNS decoder: invalid or truncated label' }
        }
        [string]::Join('.', $labels.ToArray())
    }
}

function Get-EncodedCase {
    param([string[]] $Domains, [switch] $AllowLong, [string[]] $ExpectedDomains = $Domains)
    $result = Invoke-Generator @{ Domains = $Domains; Format = 'Json'; AllowLong = $AllowLong.IsPresent }
    Assert-Equal $result.ExitCode 0 ('CLI success: ' + $result.Stderr)
    Assert-Equal $result.Stderr '' 'no stderr on success'
    $document = $result.Stdout | ConvertFrom-Json
    if ($document.domains -isnot [System.Array]) { throw 'JSON domains must always be an array' }
    Assert-Equal ($document.domains -join '|') ($ExpectedDomains -join '|') 'JSON normalized domains and order'
    [byte[]] $bytes = @($document.hexString.Split(':') | ForEach-Object { [Convert]::ToByte($_, 16) })
    Assert-Equal $document.byteLength $bytes.Length 'JSON byte length'
    Assert-Equal (@(Read-SearchList $bytes) -join '|') ($ExpectedDomains -join '|') 'independent DNS round trip'
    return [pscustomobject] @{ Document = $document; Bytes = $bytes }
}

function Test-Case {
    param([string] $Name, [scriptblock] $Test)
    & $Test
    $script:passed++
    Write-Output ('PASS ' + $Name)
}

try {
    Test-Case 'original README exact vector' {
        $case = Get-EncodedCase @('z1.prod.hotgarbagellc.net', 'prod.hotgarbagellc.net', 'hotgarbagellc.net')
        Assert-Equal ($case.Document.hexString.Replace(':', '')) '027a310470726f640d686f74676172626167656c6c63036e657400c003c008' 'original vector'
    }
    Test-Case 'RFC 3397 exact vector' {
        $case = Get-EncodedCase @('eng.apple.com', 'marketing.apple.com')
        Assert-Equal ($case.Document.hexString.Replace(':', '')) '03656e67056170706c6503636f6d00096d61726b6574696e67c004' 'RFC vector'
    }
    Test-Case 'more than two unrelated domains' {
        $null = Get-EncodedCase @('alpha.example.com', 'beta.other.net', 'gamma.third.org', 'delta.fourth.no')
    }
    Test-Case 'same label with distinct suffixes' {
        $null = Get-EncodedCase @('same.one.example', 'same.two.example', 'a.same.other', 'one.example')
    }
    Test-Case 'nested suffixes terminate at pointers' {
        $null = Get-EncodedCase @('a.b.example', 'x.b.example', 'y.x.b.example', 'b.example')
    }
    Test-Case 'duplicates preserve order' {
        $case = Get-EncodedCase @('a.example', 'a.example', 'b.example', 'a.example')
        Assert-Equal $case.Document.hexString.EndsWith(':c0:00') $true 'duplicate pointer'
    }
    Test-Case 'single-domain JSON retains array and normalizes case/root' {
        $null = Get-EncodedCase @('EXAMPLE.COM.') -ExpectedDomains @('example.com')
    }
    Test-Case 'native Unicode IDNA, dot separators and canonical punycode' {
        $unicode = 'b' + [char] 0xFC + 'cher.Example'
        $dots = 'EXAMPLE' + [char] 0x3002 + 'COM' + [char] 0xFF0E
        $null = Get-EncodedCase @($unicode, $dots, 'xn--bcher-kva.example') -ExpectedDomains @('xn--bcher-kva.example', 'example.com', 'xn--bcher-kva.example')
    }
    Test-Case 'default colon and case-insensitive Hex formats' {
        $result = Invoke-Generator @{ Domains = @('example.com') }
        Assert-Equal $result.ExitCode 0 'default success'
        Assert-Equal $result.Stdout.Trim() '07:65:78:61:6d:70:6c:65:03:63:6f:6d:00' 'colon output'
        $result = Invoke-Generator @{ Domains = @('example.com'); Format = 'hEx' }
        Assert-Equal $result.ExitCode 0 'hex success'
        Assert-Equal $result.Stdout.Trim() '076578616d706c6503636f6d00' 'hex output'
    }
    Test-Case 'no domains and invalid format fail without partial output' {
        foreach ($parameters in @(@{}, @{ Domains = @('example'); Format = 'invalid' })) {
            $result = Invoke-Generator $parameters
            Assert-Equal $result.ExitCode 2 'invalid invocation status'
            Assert-Equal $result.Stdout '' 'invalid invocation stdout'
            if ($result.Stderr -notmatch 'error:') { throw 'missing error message' }
        }
    }
    Test-Case 'invalid names fail after an otherwise valid name' {
        foreach ($domain in @('', '.', '..', 'a..b', '.example', 'example..', 'a b', "a`tb", "a`nb", '*.example', '_sip.example', '-a.example', 'a-.example', 'a/b', 'xn--', 'xn--a.example', (('a' * 64) + '.example'))) {
            $result = Invoke-Generator @{ Domains = @('good.example', $domain) }
            Assert-Equal $result.ExitCode 2 ('invalid name: ' + $domain)
            Assert-Equal $result.Stdout '' 'no partial output'
            if ($result.Stderr -notmatch 'error:') { throw 'missing validation error' }
        }
    }
    $longest = @(('a' * 63), ('b' * 63), ('c' * 63), ('d' * 61)) -join '.'
    Test-Case '255 wire bytes accepted; 256 rejected even with AllowLong' {
        $case = Get-EncodedCase @($longest)
        Assert-Equal $case.Bytes.Length 255 'maximum wire length'
        $result = Invoke-Generator @{ Domains = @(($longest + 'd')); AllowLong = $true }
        Assert-Equal $result.ExitCode 2 'excessive wire length status'
        Assert-Equal $result.Stdout '' 'excessive wire length stdout'
    }
    Test-Case 'aggregate 255-byte limit and explicit AllowLong' {
        $result = Invoke-Generator @{ Domains = @($longest, $longest) }
        Assert-Equal $result.ExitCode 2 'aggregate limit status'
        Assert-Equal $result.Stdout '' 'aggregate limit stdout'
        if ($result.Stderr -notmatch '257 bytes') { throw 'missing aggregate length in error' }
        $case = Get-EncodedCase @($longest, $longest) -AllowLong
        Assert-Equal $case.Bytes.Length 257 'long aggregate length'
    }
    Test-Case 'compression offsets above 255 use both bytes' {
        $prefix = Get-EncodedCase @($longest, 'one.test') -AllowLong
        $case = Get-EncodedCase @($longest, 'one.test', 'two.test', 'two.test') -AllowLong
        Assert-Equal $case.Bytes[$case.Bytes.Length - 2] (0xC0 -bor ($prefix.Bytes.Length -shr 8)) 'pointer high byte'
        Assert-Equal $case.Bytes[$case.Bytes.Length - 1] ($prefix.Bytes.Length -band 0xFF) 'pointer low byte'
    }
    Test-Case 'suffixes beyond 14 bits remain literal' {
        [string[]] $domains = @(0..849 | ForEach-Object { 'host{0:d4}.suffix{0:d4}' -f $_ })
        $prefix = Get-EncodedCase $domains -AllowLong
        if ($prefix.Bytes.Length -le 0x3FFF) { throw 'fixture must exceed 14-bit pointer range' }
        $case = Get-EncodedCase ($domains + @('last.unique', 'last.unique')) -AllowLong
        $tail = [BitConverter]::ToString($case.Bytes, $prefix.Bytes.Length).Replace('-', '').ToLowerInvariant()
        Assert-Equal $tail '046c61737406756e6971756500046c61737406756e6971756500' 'late suffix literals'
    }
    Write-Output ("All {0} PowerShell tests passed ({1})." -f $script:passed, $PSVersionTable.PSVersion)
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
