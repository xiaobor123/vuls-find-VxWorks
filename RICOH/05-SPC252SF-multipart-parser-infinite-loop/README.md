# RICOH SP C252SF HTTP Multipart Parser Infinite Loop

## Summary

The HTTP multipart/form-data parser in the analyzed RICOH SP C252SF firmware enters an infinite loop when a multipart part header is not terminated by a newline. The parser retries the same boundary and header without advancing the input position. A malformed HTTP request can therefore prevent the request-processing task from completing and cause a denial of service.

## Vulnerability information

| Field | Value |
|---|---|
| Vendor | RICOH Company, Ltd. |
| Product | RICOH SP C252SF |
| Analyzed image | `20030_C252SF` |
| Firmware version (analyzed image) | `V1.17` |
| Firmware SHA-256 | `f3ee1101117924fdd5a10857612a6e6f62c7fec6cc82c00c4a1a5419f7201c2d` |
| Vendor product page | [RICOH SP C250SF/C252SF downloads](https://support.ricoh.com/bb/html/dr_ut_e/apc/model/spc250sf/spc250sf.htm) |
| Affected component | HTTP multipart/form-data parser |
| Vulnerability type | Infinite loop / denial of service |
| CWE | CWE-835: Loop with Unreachable Exit Condition |
| Attack vector | Network, if the affected HTTP handler is reachable |

## Test files

- [Analyzed firmware image: `20030_C252SF`](./firmware/20030_C252SF)  
  SHA-256: `f3ee1101117924fdd5a10857612a6e6f62c7fec6cc82c00c4a1a5419f7201c2d`
- [Recovered symbol table: `symbols.txt`](./firmware/symbols.txt)  
  SHA-256: `02462b52f7dac7fc2e9c0a35cc2cd2267fb9c0a28daa9bfef3653d938a4691d2`

The symbol table contains the recovered function-name-to-address mapping used during analysis and rehosting. It is not an original vendor debug-symbol package.

## Technical details

The vulnerable parser is `websParseMultipartFormData`, beginning at `0x9503F0`. At `0x950584`, the parser searches the current multipart header for a newline. If the search fails, execution reaches `0x9508E0` while preserving the current header pointer. The parser then finds the same boundary and branches back to `0x950550`, causing the same malformed header to be parsed again without consuming input.

```text
0x950584  search current part header for '\n'
     |
     | newline not found
     v
0x9508E0  retain the current header pointer
     |
     | the same boundary is found again
     v
0x9508FC -> 0x950550  parse the same part again
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
