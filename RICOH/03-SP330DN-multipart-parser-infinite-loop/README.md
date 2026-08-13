# RICOH SP 330DN HTTP Multipart Parser Infinite Loop

## Summary

The HTTP multipart/form-data parser in the analyzed RICOH SP 330DN firmware enters an infinite loop when a multipart part header is missing its terminating newline. The parser returns to the same loop without consuming additional input. A malformed request can therefore prevent the HTTP request-processing task from completing and cause a denial of service.

## Vulnerability information

| Field | Value |
|---|---|
| Report ID | RICOH-03 |
| Vendor | RICOH Company, Ltd. |
| Product | RICOH SP 330DN |
| Analyzed image | `20030_SP330DN` |
| Firmware SHA-256 | `764771134ca39b2d334ce94592768c8931d4415e64d39b3a4e5899e020af7868` |
| Affected component | HTTP multipart/form-data parser |
| Vulnerability type | Infinite loop / denial of service |
| CWE | CWE-835: Loop with Unreachable Exit Condition |
| Attack vector | Network, if the affected HTTP handler is reachable |

## Technical details

At `0x5F75F4`, the parser searches the current multipart header for a newline. If the search fails, execution follows the path below and re-enters the parsing loop:

```text
0x5F75F4  search for '\n'
     |
     | newline not found
     v
0x5F75FC -> 0x5F76B4 -> 0x5F76B8 -> 0x5F75AC
                                            |
                                            +-- parse the same bytes again
```

The register holding the current input position remains unchanged across this path. The next iteration therefore observes the same malformed bytes and makes no progress.

A simplified representation is:

```c
for (;;) {
    char *newline = find_newline(cursor);
    if (newline == NULL) {
        continue;  /* cursor is unchanged */
    }
    cursor = newline + 1;
}
```

## Reproduction

The included [`poc.py`](./poc.py) constructs a multipart request whose `Content-Disposition` line is missing its line terminator.

```bash
python3 poc.py
python3 poc.py --host <target> --port 80 --path /goform/upload --send
```

The script does not transmit anything unless `--send` is supplied. Use it only against an authorized target. The externally reachable URI and authentication requirements must be confirmed on the physical product.

## Observed result

- Samples `3c01b44127a203f6` and `669669f620078fcc` did not reach the configured `TestFinish` location and were terminated by the external timeout process.
- The timeout was an execution hang; it was not a QEMU crash.
- Adding a single newline byte to `3c01b44127a203f6`, without otherwise changing the request, caused the same firmware execution to reach `TestFinish` at `0x5F2354`.
- The one-byte differential result matches the statically identified no-progress loop and directly associates the hang with the missing line terminator.

Relevant artifacts:

- [Original objective 3c01b44127a203f6](./evidence/SP330_3c01b44127a203f6)
- [Timeout replay excerpt](./evidence/SP330_3c01b44127a203f6_excerpt.txt)
- [One-byte newline differential replay](./evidence/SP330_3c_newline_excerpt.txt)
- [Original objective 669669f620078fcc](./evidence/SP330_669669f620078fcc)
- [Second timeout replay excerpt](./evidence/SP330_669669f620078fcc_excerpt.txt)
- [Evidence manifest](./evidence/manifest.json)

## Security impact

A remote party able to reach the affected multipart handler can cause the HTTP request-processing task to loop indefinitely. The management service may become unresponsive, and shared dispatch or worker-task designs may allow the hang to affect additional connections. Recovery may require restarting the affected task or rebooting the device.

## Remediation

1. Abort multipart parsing when a required line terminator is absent.
2. Enforce the invariant that each loop iteration either consumes input or returns an error.
3. Limit multipart header length, part count, and total parser iterations.
4. Add regression tests for truncated part headers, missing CR/LF sequences, and premature end-of-input.

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
