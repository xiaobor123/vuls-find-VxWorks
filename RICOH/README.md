# RICOH VxWorks Firmware Vulnerability Reports

This directory contains six product-level vulnerability reports that were dynamically reproduced in a full-system firmware rehosting environment. The HTTP multipart parser defect was confirmed in four RICOH SP firmware images; the HTTP request-target overflow was confirmed in two images. Each report includes the exact analyzed firmware hash, technical root cause, reproduction instructions, execution evidence, security impact, and remediation guidance.

Where the vendor no longer publishes the exact legacy firmware package, the corresponding report links to the authoritative product download page and identifies the analyzed image using its embedded firmware version and SHA-256 digest. A link to a newer release must not be interpreted as the source of the analyzed legacy binary.

| ID | Affected product | Vulnerability | CWE | Validation |
|---|---|---|---|---|
| RICOH-01 | RICOH SP 221 firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced |
| RICOH-02 | RICOH SP 221 firmware sample | HTTP request-target stack buffer overflow | CWE-121 | Dynamically reproduced with input-controlled PC |
| RICOH-03 | RICOH SP 330DN firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced with differential input |
| RICOH-04 | RICOH SP 330DN firmware sample | HTTP request-target stack buffer overflow | CWE-121 | Dynamically reproduced with input-controlled PC |
| RICOH-05 | RICOH SP C252SF firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced with differential input |
| RICOH-06 | RICOH Aficio SP 3500SF firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced with differential input |

## Important validation boundary

The findings were reproduced against extracted firmware images in a full-system rehosting environment. The vulnerable firmware code and its failure behavior are confirmed. The following deployment properties still require confirmation on authorized physical devices or by RICOH:

- the exact commercial model and firmware-version mapping of `20030_SP221`;
- whether the affected HTTP handlers are enabled by default;
- whether authentication is required before the affected paths can be reached;
- request-length limits imposed by any component outside the analyzed firmware; and
- the complete range of affected firmware releases.

These uncertainties affect severity scoring and exploitability, but do not invalidate the underlying code defects demonstrated in the reports.

## CVE counting note

The four multipart findings share the same parser defect pattern and should normally be disclosed as one vulnerability affecting four product firmware images unless RICOH confirms that they are independently maintained defects requiring separate fixes. The two request-target overflows likewise share a defect pattern; the final CVE grouping remains a CNA decision.

| Product sample | Analyzed version | Newline search | No-progress parser cycle | Confirmation |
|---|---:|---:|---|---|
| RICOH SP 221 | V1.06 | `0x1D04C4` | `0x1D047C`--`0x1D0584` | Dynamic replay and corrected-input differential |
| RICOH SP C252SF | V1.17 | `0x950584` | `0x950550`--`0x9508FC` | Dynamic replay and corrected-input differential |
| RICOH SP 330DN | V1.11 | `0x5F75F4` | `0x5F75AC`--`0x5F76B8` | Dynamic replay and corrected-input differential |
| RICOH Aficio SP 3500SF | V2.14 | `0x380FC8` | `0x380F88`--`0x381368` | Dynamic replay and corrected-input differential |

## Contents

- [RICOH-01: SP 221 HTTP multipart parser infinite loop](./01-SP221-multipart-parser-infinite-loop/README.md)
- [RICOH-02: SP 221 HTTP request-target stack buffer overflow](./02-SP221-http-uri-stack-overflow/README.md)
- [RICOH-03: SP 330DN HTTP multipart parser infinite loop](./03-SP330DN-multipart-parser-infinite-loop/README.md)
- [RICOH-04: SP 330DN HTTP request-target stack buffer overflow](./04-SP330DN-http-uri-stack-overflow/README.md)
- [RICOH-05: SP C252SF HTTP multipart parser infinite loop](./05-SPC252SF-multipart-parser-infinite-loop/README.md)
- [RICOH-06: Aficio SP 3500SF HTTP multipart parser infinite loop](./06-SP3500SF-multipart-parser-infinite-loop/README.md)

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
