# DHCP option 119 generator

Generate the hexadecimal payload for DHCP option 119, the DNS search domain
list. Runs locally on macOS and Linux with **Python 3.9 or newer**, or on Windows
with **Windows PowerShell 5.1 or PowerShell 7**, using only built-in libraries.
The PowerShell version also runs wherever PowerShell 7 is installed, including
macOS and Linux. No Node.js, packages, service or network access is needed.

Python 3 is a prerequisite; recent macOS releases do not guarantee a bundled
Python installation. Check `python3 --version` and install Python from
[python.org](https://www.python.org/downloads/) or your system's package manager
if needed.

## Quick start

From this directory on macOS or Linux:

```sh
python3 dhcp-option-119-generate.py z1.prod.hotgarbagellc.net prod.hotgarbagellc.net hotgarbagellc.net
```

Output is a single copyable line of lowercase, colon-separated hex:

```text
02:7a:31:04:70:72:6f:64:0d:68:6f:74:67:61:72:62:61:67:65:6c:6c:63:03:6e:65:74:00:c0:03:c0:08
```

The executable script also works as `./dhcp-option-119-generate.py` with the
same arguments. In your DHCP server, select option **119** and its hex/byte
value type, then paste the payload using the separator format that server
expects. The output excludes the option code and length fields.

```sh
# Hex without separators
python3 dhcp-option-119-generate.py --format hex eng.apple.com marketing.apple.com
# 03656e67056170706c6503636f6d00096d61726b6574696e67c004

# Machine-readable output
python3 dhcp-option-119-generate.py --format json EXAMPLE.com.
# {"domains": ["example.com"], "hexString": "07:65:78:61:6d:70:6c:65:03:63:6f:6d:00", "byteLength": 13}

python3 dhcp-option-119-generate.py --help
```

### Windows PowerShell

From PowerShell in this directory; Python is not required:

```powershell
.\dhcp-option-119-generate.ps1 -Domains @('eng.apple.com', 'marketing.apple.com')
# 03:65:6e:67:05:61:70:70:6c:65:03:63:6f:6d:00:09:6d:61:72:6b:65:74:69:6e:67:c0:04

.\dhcp-option-119-generate.ps1 -Domains @('eng.apple.com', 'marketing.apple.com') -Format Hex
.\dhcp-option-119-generate.ps1 -Domains @('EXAMPLE.com.') -Format Json
# {"domains":["example.com"],"hexString":"07:65:78:61:6d:70:6c:65:03:63:6f:6d:00","byteLength":13}

Get-Help .\dhcp-option-119-generate.ps1 -Full
```

`-Domains` accepts a PowerShell string array. A single positional domain also
works: `.\dhcp-option-119-generate.ps1 example.com`. `-Format` accepts `Colon`
(the default), `Hex` or `Json`, case insensitively. Use `-AllowLong` for the
explicit long-payload behavior described below. No arguments produces a
validation error without prompting for input.

If script execution is blocked, run it with the policy bypassed for that one
call and give the domains as plain arguments:
`powershell.exe -ExecutionPolicy Bypass -File .\dhcp-option-119-generate.ps1 eng.apple.com marketing.apple.com`.

## Domains and compression

Provide one or more domains in search preference order. Order and duplicates
are preserved. Domains are lowercased, and an optional final root dot is
removed. Unicode domains use Python's standard-library **IDNA2003** conversion
(RFC 3490), for example `bücher.example` becomes `xn--bcher-kva.example`.
This differs from IDNA2008: `faß.de` becomes `fass.de`. Supplied ASCII/punycode
names must also pass the standard-library IDNA2003 codec's validity checks;
IDNA2008-only names require a tool with IDNA2008 support.
The Unicode dot equivalents recognized by IDNA are accepted as separators.

The PowerShell version uses native **`System.Globalization.IdnMapping`** with
STD3 rules and validates supplied punycode by a native decode/encode round trip.
Its Unicode rules depend on the Windows/.NET runtime and globalization backend;
they can differ from Python's IDNA2003 rules and from another PowerShell runtime.
For example, PowerShell 7.6.6 on this Mac converts `faß.de` to `xn--fa-hia.de`,
while Python converts it to `fass.de`. Use validated ASCII/punycode inputs for
consistent wire encoding; inputs accepted by both versions produce identical
bytes once normalized to the same ASCII domains.

Encoded labels must have 1–63 ASCII bytes, contain letters, digits or interior
hyphens, and each uncompressed domain must fit within 255 wire bytes including
its length bytes and root terminator. Empty labels, the root alone, whitespace,
wildcards, underscores, edge hyphens and invalid punycode are rejected.
Validation errors go to stderr with exit status 2 and no partial stdout.

Compression uses previously emitted **complete domain suffixes**. Pointers
terminate their name and use a 14-bit offset into the option payload. Repeated
labels with different suffixes stay distinct; domains after the second are
encoded normally. Suffixes beginning beyond offset 16383 are emitted literally
unless an earlier usable suffix exists.

The compressed payload is limited to **255 bytes** by default, the capacity of
one DHCP option field. `--allow-long` explicitly permits a longer concatenated
payload, but only use it if your DHCP server supports splitting option 119
across multiple fields using RFC 3396. This tool produces the aggregate bytes;
it does not add DHCP headers or split the fields for you. Server input and
client search-list limits may impose additional restrictions.

## Development and migration

```sh
python3 -m unittest discover -s tests -v
```

`normalize_domain()` and `encode_search_list()` can also be loaded from the
Python script; the encoder returns `bytes` and defaults to the same 255-byte
limit as the CLI.

Run the PowerShell CLI regression suite without Python or Pester:

```powershell
# Windows PowerShell 5.1
powershell.exe -NoProfile -File .\tests\test_generate_powershell.ps1
# PowerShell 7 (Windows, macOS or Linux)
pwsh -NoProfile -File ./tests/test_generate_powershell.ps1
```

The suite checks exact RFC/original vectors, independent DNS decoding, input
validation, formats, JSON arrays and both compression-offset boundaries. It
launches the same PowerShell runtime as the test process, so run it under each
runtime you want to verify. PowerShell 7.6.6 on macOS was tested locally;
Windows PowerShell 5.1 compatibility uses supported syntax/APIs but has not been
verified on a Windows host.

This rewrite replaces the original Node.js script and the short Python and
PowerShell ports that followed it. The old Node.js encoder
indexed individual labels instead of whole suffixes, skipped domains after the
second, could continue after a pointer, and did not validate names or encode
both bytes of larger compression offsets correctly. Its example happened to
match the expected output, but unrelated domains could produce invalid data.
The short ports already compressed whole suffixes, so valid ASCII domains give
the same bytes as before, but they did not validate names, convert Unicode or
limit the payload length.
The CLI now defaults to the payload alone; use `--format json` for structured
output in place of the old JavaScript object display and of the `domains:` and
`hexString:` lines the short ports printed.

## References and credits

- [RFC 3397: DHCP Domain Search Option](https://www.rfc-editor.org/rfc/rfc3397)
- [RFC 1035 §4.1.4: DNS message compression](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4)
- [RFC 3396: Encoding long DHCP options](https://www.rfc-editor.org/rfc/rfc3396)
- [RFC 3490: IDNA2003](https://www.rfc-editor.org/rfc/rfc3490)
- [Microsoft: IdnMapping.GetAscii and runtime IDNA behavior](https://learn.microsoft.com/en-us/dotnet/api/system.globalization.idnmapping.getascii)
- Original implementation: Ken Malinich, copyright 2020, under the unchanged
  [MIT license](LICENSE).
- Original acknowledgements: [u/NoTheOtherRick's Reddit comment](https://old.reddit.com/r/fortinet/comments/bskbzg/dhcp_option_119_domain_search/esor6rp/)
  and [BrechtSchamp on the Meraki community forums](https://community.meraki.com/t5/Security-SD-WAN/DHCP-Option-43-and-Sub-option/m-p/47562/highlight/true#M11987).
