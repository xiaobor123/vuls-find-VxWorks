# RICOH Aficio SP 3500SF HTTP Multipart Parser Infinite Loop

## Summary

The HTTP multipart/form-data parser in the analyzed RICOH Aficio SP 3500SF firmware enters an infinite loop when a multipart part header is not terminated by a newline. The parser retries the same boundary and header without advancing the input position. A malformed HTTP request can therefore prevent the request-processing task from completing and cause a denial of service.

## Vulnerability information

| Field | Value |
|---|---|
| Vendor | RICOH Company, Ltd. |
| Product | RICOH Aficio SP 3500SF |
| Analyzed image | `sp_3500` |
| Firmware version (analyzed image) | `V2.14` |
| Firmware SHA-256 | `887d6e512c331b0fd2b61797fa54cd20926fa037b6388a80a9f395f124f9ff78` |
| Vendor product page | [RICOH Aficio SP 3500SF/3510SF downloads](https://support.ricoh.com/bb/html/dr_ut_e/apc/model/sp35s/sp35s.htm) |
| Affected component | HTTP multipart/form-data parser |
| Vulnerability type | Infinite loop / denial of service |
| CWE | CWE-835: Loop with Unreachable Exit Condition |
| Attack vector | Network, if the affected HTTP handler is reachable |

## Test files

- [Analyzed firmware image: `sp_3500`](./firmware/sp_3500)  
  SHA-256: `887d6e512c331b0fd2b61797fa54cd20926fa037b6388a80a9f395f124f9ff78`
- [Recovered symbol table: `symbols.txt`](./firmware/symbols.txt)  
  SHA-256: `e9183f0e630924692ad97e884224f07ffe31eb61ad9dfb3c3ea34071b8654536`

The symbol table contains the recovered function-name-to-address mapping used during analysis and rehosting. It is not an original vendor debug-symbol package.

## Technical details

The vulnerable multipart parser begins at `0x380E40`. At `0x380FC8`, it searches the current multipart part header for a newline. If the search fails, execution reaches `0x381350` with the current header pointer unchanged. The parser then finds the same boundary and branches back to `0x380F88`, causing the same malformed header to be processed repeatedly.

```text
0x380FC8  search current part header for '\n'
     |
     | newline not found
     v
0x381350  retain the current header pointer
     |
     | the same boundary is found again
     v
0x381368 -> 0x380F88  parse the same part again
```

A simplified representation is:

```c
while (current_part != NULL) {
    char *newline = strchr(current_part, '\n');
    if (newline == NULL) {
        /* current_part is retained and the same boundary is found again */
        continue;
    }
    current_part = newline + 1;
}
```

## Reproduction

The included [`poc.py`](./poc.py) generates a multipart request whose `Content-Disposition` line has no line terminator. The corresponding [`malformed-request.bin`](./evidence/malformed-request.bin) leaves the parser running until the external timeout. The control request in [`corrected-request.bin`](./evidence/corrected-request.bin) appends the missing CRLF and adjusts `Content-Length` accordingly; it reaches the configured normal completion point.

```bash
python3 poc.py
python3 poc.py --host <target> --port 80 --send
```

- [Malformed-request replay log](./evidence/malformed-replay.log)
- [Corrected-request replay log](./evidence/corrected-replay.log)

## Security impact

A remote party able to reach the affected multipart handler can cause the HTTP request-processing task to loop indefinitely. The management service may become unresponsive, and recovery may require restarting the affected task or rebooting the device.

## Remediation

1. Abort multipart parsing when a required line terminator is absent.
2. Require each parser iteration to consume input or return an error.
3. Limit multipart header length, part count, and parser iterations.
4. Add regression tests for truncated part headers and missing CR/LF sequences.

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
