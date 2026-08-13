# RICOH VxWorks Firmware Vulnerability Reports

This directory contains four vulnerability reports that were dynamically reproduced in a full-system firmware rehosting environment. Each report includes the exact analyzed firmware hash, technical root cause, reproduction instructions, execution evidence, security impact, and remediation guidance.

| ID | Affected product | Vulnerability | CWE | Validation |
|---|---|---|---|---|
| RICOH-01 | RICOH SP 221 firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced |
| RICOH-02 | RICOH SP 221 firmware sample | HTTP request-target stack buffer overflow | CWE-121 | Dynamically reproduced with input-controlled PC |
| RICOH-03 | RICOH SP 330DN firmware sample | HTTP multipart parser infinite loop | CWE-835 | Dynamically reproduced with differential input |
| RICOH-04 | RICOH SP 330DN firmware sample | HTTP request-target stack buffer overflow | CWE-121 | Dynamically reproduced with input-controlled PC |

## Important validation boundary

The findings were reproduced against extracted firmware images in a full-system rehosting environment. The vulnerable firmware code and its failure behavior are confirmed. The following deployment properties still require confirmation on authorized physical devices or by RICOH:

- the exact commercial model and firmware-version mapping of `20030_SP221`;
- whether the affected HTTP handlers are enabled by default;
- whether authentication is required before the affected paths can be reached;
- request-length limits imposed by any component outside the analyzed firmware; and
- the complete range of affected firmware releases.

These uncertainties affect severity scoring and exploitability, but do not invalidate the underlying code defects demonstrated in the reports.

## CVE counting note

The two multipart findings have the same defect pattern, as do the two request-target overflows. A CNA may assign four CVE IDs because the defects were confirmed in separate product firmware images, or merge affected products under fewer CVE IDs if RICOH confirms that they originate from the same maintained component and are fixed by the same change.

## Contents

- [RICOH-01: SP 221 HTTP multipart parser infinite loop](./01-SP221-multipart-parser-infinite-loop/README.md)
- [RICOH-02: SP 221 HTTP request-target stack buffer overflow](./02-SP221-http-uri-stack-overflow/README.md)
- [RICOH-03: SP 330DN HTTP multipart parser infinite loop](./03-SP330DN-multipart-parser-infinite-loop/README.md)
- [RICOH-04: SP 330DN HTTP request-target stack buffer overflow](./04-SP330DN-http-uri-stack-overflow/README.md)

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`

