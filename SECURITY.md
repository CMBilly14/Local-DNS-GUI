# Security Policy

## Supported versions

Security fixes are provided for the most recent published version of DNS Local.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Older versions | No |

## Reporting a vulnerability

Please do not disclose an exploitable vulnerability in a public GitHub issue.
Use the repository's **Security** tab and select **Report a vulnerability** to
send the maintainers a private report.

Include as much of the following information as possible:

- DNS Local version
- Operating system and version
- Steps needed to reproduce the issue
- Expected and observed behavior
- Potential security impact
- Relevant logs or sample DNS data with sensitive information removed

Examples of security reports include arbitrary code execution, unsafe rendering
of DNS-controlled content, bypasses of renderer or preload isolation, unintended
file access or overwrite, disclosure of local data, and exploitable dependency
vulnerabilities.

Please allow reasonable time to investigate and prepare a correction before
public disclosure. Reports are reviewed as availability permits; no fixed
response or resolution time is promised.

## Reporting ordinary bugs

Use a public GitHub issue for general application problems, incorrect results,
interface problems, feature requests, and other behavior that does not cross a
security boundary. For example, an SPF search displaying unrelated TXT records
is a functional bug and belongs in a normal issue unless it can also be used to
execute code, expose protected information, overwrite files, or bypass an
application security control.

Do not include private domains, credentials, internal IP addresses, or other
sensitive information in public issues. Use private vulnerability reporting if
you are unsure whether the information is safe to publish.

## Expected behavior and limitations

The following generally do not indicate a security vulnerability:

- Windows warnings caused by the unsigned executable
- DNS answers differing between recursive and authoritative servers
- DNS queries being visible to the selected DNS server
- Networks blocking direct UDP or TCP port 53 traffic
- The absence of local DNSSEC chain validation
- Results affected by DNS caching, filtering, split DNS, VPNs, or geography

DNS responses and domain names are treated as untrusted input. Reports showing
that untrusted data crosses an application security boundary are welcome through
private vulnerability reporting.
