#Requires -Version 5.1
<#
.SYNOPSIS
Generate the DNS-encoded hexadecimal payload of DHCP option 119 (RFC 3397).
.DESCRIPTION
Runs with Windows PowerShell 5.1 or PowerShell 7, without external dependencies.
Preserves search order and duplicates, compressing complete previously emitted
domain suffixes. Output excludes the DHCP option code and length fields.
Unicode names use the runtime's System.Globalization.IdnMapping implementation.
.PARAMETER Domains
One or more search domains in preference order. Use a PowerShell string array.
.PARAMETER Format
Colon (default), Hex without separators, or Json with domains, hexString and
byteLength properties. Format names are case insensitive.
.PARAMETER AllowLong
Permit aggregate payloads over 255 bytes. Requires a DHCP server supporting
RFC 3396 concatenation; this script does not add headers or split option fields.
.EXAMPLE
.\dhcp-option-119-generate.ps1 -Domains @('eng.apple.com', 'marketing.apple.com')
.EXAMPLE
.\dhcp-option-119-generate.ps1 example.com -Format Json
.NOTES
Invalid domains produce no stdout and exit status 2. Supplied punycode labels
must survive a native IDNA decode/encode round trip. Unicode behavior can differ
between Windows PowerShell, PowerShell 7 and the Python version of this tool.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]] $Domains = @(),

    [string] $Format = 'Colon',

    [switch] $AllowLong
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertTo-NormalizedDomain {
    param([AllowEmptyString()][string] $Domain)

    if ([string]::IsNullOrEmpty($Domain) -or $Domain -match '\s') {
        throw 'domains must be nonempty and contain no whitespace'
    }
    foreach ($separator in @(0x3002, 0xFF0E, 0xFF61)) {
        $Domain = $Domain.Replace([char] $separator, [char] '.')
    }
    if ($Domain.EndsWith('.')) {
        $Domain = $Domain.Substring(0, $Domain.Length - 1)
    }

    $idn = New-Object System.Globalization.IdnMapping
    $idn.UseStd3AsciiRules = $true
    $asciiLabels = New-Object 'System.Collections.Generic.List[string]'
    $wireLength = 1
    foreach ($label in $Domain.Split('.')) {
        if ($label.Length -eq 0) {
            throw 'domains must contain nonempty labels; the root alone is not allowed'
        }
        try {
            $asciiLabel = $idn.GetAscii($label).ToLowerInvariant()
            if ($asciiLabel.StartsWith('xn--')) {
                $decoded = $idn.GetUnicode($asciiLabel)
                if ($idn.GetAscii($decoded).ToLowerInvariant() -cne $asciiLabel) {
                    throw 'noncanonical punycode'
                }
            }
        }
        catch {
            throw "invalid IDNA label: '$label'"
        }
        if ($asciiLabel.Length -lt 1 -or $asciiLabel.Length -gt 63) {
            throw 'each encoded label must contain 1 to 63 bytes'
        }
        if ($asciiLabel -cnotmatch '\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z') {
            throw "labels must use letters, digits or interior hyphens: '$label'"
        }
        $asciiLabels.Add($asciiLabel)
        $wireLength += 1 + $asciiLabel.Length
    }
    if ($wireLength -gt 255) {
        throw 'an uncompressed domain must fit within 255 wire bytes'
    }
    return [string]::Join('.', $asciiLabels.ToArray())
}

function ConvertTo-SearchListBytes {
    param([string[]] $NormalizedDomains, [bool] $PermitLong)

    $payload = New-Object 'System.Collections.Generic.List[byte]'
    $suffixOffsets = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    foreach ($domain in $NormalizedDomains) {
        $labels = $domain.Split('.')
        $compressed = $false
        for ($index = 0; $index -lt $labels.Length; $index++) {
            $suffix = [string]::Join('.', $labels[$index..($labels.Length - 1)])
            if ($suffixOffsets.ContainsKey($suffix)) {
                $target = $suffixOffsets[$suffix]
                $payload.Add([byte] (0xC0 -bor ($target -shr 8)))
                $payload.Add([byte] ($target -band 0xFF))
                $compressed = $true
                break
            }
            if ($payload.Count -le 0x3FFF) {
                $suffixOffsets.Add($suffix, $payload.Count)
            }
            $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($labels[$index])
            $payload.Add([byte] $labelBytes.Length)
            $payload.AddRange($labelBytes)
        }
        if (-not $compressed) {
            $payload.Add([byte] 0)
        }
    }
    if ($payload.Count -gt 255 -and -not $PermitLong) {
        throw (("encoded payload is {0} bytes (maximum 255); use -AllowLong only " +
            'with a DHCP server supporting RFC 3396 concatenation') -f $payload.Count)
    }
    # Preserve the byte array as one return value despite pipeline enumeration.
    return ,$payload.ToArray()
}

try {
    if ($Format -notin @('Colon', 'Hex', 'Json')) {
        throw '-Format must be Colon, Hex or Json'
    }
    if ($Domains.Count -eq 0) {
        throw 'at least one search domain is required'
    }
    [string[]] $normalized = @(foreach ($domain in $Domains) {
        ConvertTo-NormalizedDomain -Domain $domain
    })
    [byte[]] $payload = ConvertTo-SearchListBytes -NormalizedDomains $normalized -PermitLong $AllowLong.IsPresent
    $colonHex = [System.BitConverter]::ToString($payload).Replace('-', ':').ToLowerInvariant()
    switch ($Format) {
        'Json' {
            [ordered] @{
                domains = $normalized
                hexString = $colonHex
                byteLength = $payload.Length
            } | ConvertTo-Json -Compress
        }
        'Hex' { $colonHex.Replace(':', '') }
        default { $colonHex }
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine(('error: {0}' -f $_.Exception.Message))
    exit 2
}
