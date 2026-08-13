# RICOH SP 221 HTTP Multipart Parser Infinite Loop

## Summary

An HTTP multipart/form-data parser in the analyzed RICOH SP 221 firmware enters an infinite loop when a multipart part header is not terminated by a newline. After the parser fails to find the expected newline, it returns to the same loop with an unchanged input cursor. A malformed HTTP request can therefore keep the HTTP request-processing task executing indefinitely and cause a denial of service.

## Vulnerability information

| Field | Value |
|---|---|
| Report ID | RICOH-01 |
| Vendor | RICOH Company, Ltd. |
| Product | RICOH SP 221-family firmware; exact commercial SKU requires vendor confirmation |
| Analyzed image | `20030_SP221` |
| Firmware SHA-256 | `f7142be9b54c962d03a70dac664b50b3f43ab0f5ca3ebaf48727f2677ebad0a1` |
| Affected component | HTTP multipart/form-data parser |
| Vulnerability type | Infinite loop / denial of service |
| CWE | CWE-835: Loop with Unreachable Exit Condition |
| Attack vector | Network, if the affected HTTP handler is reachable |

## Test files

- [Analyzed firmware image: `20030_SP221`](./firmware/20030_SP221)  
  SHA-256: `f7142be9b54c962d03a70dac664b50b3f43ab0f5ca3ebaf48727f2677ebad0a1`
- [Recovered symbol table: `symbols.txt`](./firmware/symbols.txt)  
  SHA-256: `4ced414340407c7d3e7586d6d13c195f86e80172764812ac7b77b4ab9e4129ca`

The symbol table contains the recovered function-name-to-address mapping used during analysis and rehosting. It is not an original vendor debug-symbol package.

## Technical details

The multipart parser searches the current part header for a newline at address `0x1D04C4`. When the search returns `NULL`, the error path does not reject the malformed request and does not advance the parser cursor. Control flow follows:

```text
0x1D04C4  search for '\n'
     |
     | newline not found
     v
0x1D04CC -> 0x1D0580 -> 0x1D0584 -> 0x1D047C
                                            |
                                            +-- parse the same bytes again
```

Because the cursor is unchanged, the exit condition cannot become true. The HTTP task repeatedly executes the same parser region until the emulator or an external watchdog terminates it.

A simplified representation of the defect is:

```c
while (part_header != NULL) {
    char *newline = strchr(part_header, '\n');
    if (newline == NULL) {
        continue;  /* part_header is unchanged */
    }
    part_header = newline + 1;
}
```

## Reproduction

The included [`poc.py`](./poc.py) creates a multipart request whose `Content-Disposition` line deliberately lacks the terminating CRLF.

Generate the request without sending it:

```bash
python3 poc.py
```

Send it only to an authorized test device or rehosting instance:

```bash
python3 poc.py --host <target> --port 80 --path /goform/upload --send
```

The exact externally reachable URI may differ by firmware configuration. `/goform/upload` is the path used by the reproduced firmware input.

## Observed result

- Objective samples `82e504615a415f11` and `fcef766a223169bc` repeatedly executed without reaching the configured normal completion point.
- The emulator was eventually terminated by the external timeout process with `SIGTERM`; this was a hang, not an emulator crash.
- Static execution analysis located the no-progress loop at `0x1D047C-0x1D0584`.
- In differential testing, adding only the missing line terminator allowed the request-processing execution to finish normally.

Relevant artifacts:

- [Original objective 82e504615a415f11](./evidence/SP221_82e504615a415f11)
- [Replay excerpt for 82e504615a415f11](./evidence/SP221_82e504615a415f11_excerpt.txt)
- [Original objective fcef766a223169bc](./evidence/SP221_fcef766a223169bc)
- [Replay excerpt for fcef766a223169bc](./evidence/SP221_fcef766a223169bc_excerpt.txt)
- [Evidence manifest](./evidence/manifest.json)

## Security impact

A remote party able to reach the affected HTTP multipart handler can cause the request-processing task to consume CPU indefinitely. This can make the management HTTP service unresponsive and may also affect other services if they share the same dispatcher or worker task. Recovery may require a task restart or device reboot.

No claim of unauthenticated reachability is made until the physical-device routing and authentication requirements are confirmed.

## Remediation

1. Treat a missing multipart header terminator as a parsing error and close the current request.
2. Require every successful parser iteration to advance the input cursor.
3. Enforce maximum multipart header lengths and parser-iteration limits.
4. Add regression tests for truncated headers, missing CR/LF sequences, oversized headers, and premature end-of-input.

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
