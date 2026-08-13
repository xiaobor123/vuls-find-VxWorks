# RICOH SP 221 HTTP Request-Target Stack Buffer Overflow

## Summary

The analyzed RICOH SP 221 firmware copies an attacker-controlled HTTP request target into a fixed-size stack buffer without validating its length. A sufficiently long URI overwrites the saved return address. Repeated tests using different fill bytes produced corresponding program-counter values, demonstrating input-controlled control-flow corruption.

## Vulnerability information

| Field | Value |
|---|---|
| Report ID | RICOH-02 |
| Vendor | RICOH Company, Ltd. |
| Product | RICOH SP 221-family firmware; exact commercial SKU requires vendor confirmation |
| Analyzed image | `20030_SP221` |
| Firmware SHA-256 | `f7142be9b54c962d03a70dac664b50b3f43ab0f5ca3ebaf48727f2677ebad0a1` |
| Affected component | HTTP resource-request processing |
| Vulnerability type | Stack-based buffer overflow |
| CWE | CWE-121: Stack-based Buffer Overflow |
| Attack vector | Network, if the HTTP service is reachable |

## Test files

- [Analyzed firmware image: `20030_SP221`](./firmware/20030_SP221)  
  SHA-256: `f7142be9b54c962d03a70dac664b50b3f43ab0f5ca3ebaf48727f2677ebad0a1`
- [Recovered symbol table: `symbols.txt`](./firmware/symbols.txt)  
  SHA-256: `4ced414340407c7d3e7586d6d13c195f86e80172764812ac7b77b4ab9e4129ca`

The symbol table contains the recovered function-name-to-address mapping used during analysis and rehosting. It is not an original vendor debug-symbol package.

## Technical details

The vulnerable function, identified as `HTTPfetchResource`, begins at `0x1CEB4C`. At `0x1CF070`, it invokes `strcpy` to copy the parsed HTTP resource path into a fixed-size local stack buffer. No destination-capacity or source-length check is performed.

The distance from the local destination buffer to the saved return address is approximately `0x1B0` (432) bytes. The function later returns at `0x1CEFC4` using an instruction that restores the program counter from the stack. Consequently, an oversized request target overwrites the saved return address before the function returns.

A simplified representation is:

```c
int HTTPfetchResource(const char *request_target) {
    char path[FIXED_SIZE];
    strcpy(path, request_target);  /* no length validation */
    return serve_resource(path);
}
```

## Reproduction

The included [`poc.py`](./poc.py) generates a syntactically valid HTTP GET request with a long request target. It writes `payload.bin` by default and sends data only when `--send` is explicitly provided.

```bash
python3 poc.py
python3 poc.py --host <target> --port 80 --length 440 --byte A --send
```

Use only against an authorized device or rehosting instance. The default length reproduces the overwrite in the analyzed environment; an external server or a different firmware build may impose a different limit.

## Observed result

Four controlled replays used 440 repeated `A`, `B`, `C`, and `D` bytes in the request target. The resulting invalid program-counter values reflected the supplied bytes:

| Input pattern | Observed PC |
|---|---|
| `A` | `0x41414140` |
| `B` | `0x42424242` |
| `C` | `0x43434342` |
| `D` | `0x44444444` |

The small alignment-dependent differences in the least significant bit do not change the conclusion: the saved return address is overwritten by request data. The replay excerpt records the `A`-pattern reproduction and the resulting out-of-range PC.

Relevant artifacts:

- [Generated proof-of-concept payload](./payload.bin)
- [Replay excerpt showing PC 0x41414140](./evidence/SP221_long_uri_A_excerpt.txt)
- [Evidence manifest](./evidence/manifest.json)

## Security impact

At minimum, a remote request can crash the HTTP service or the task that processes the request. Because the attacker controls the saved return address, control-flow hijacking and arbitrary code execution may be possible on deployments without effective stack protection, address randomization, or executable-memory restrictions. This report demonstrates control of the program counter but does not claim a working code-execution exploit.

## Remediation

1. Reject request targets that exceed a documented maximum length.
2. Replace unbounded string copies with operations that receive the destination capacity and always terminate the output.
3. Revalidate length after URL decoding, canonicalization, and path normalization.
4. Enable stack canaries and other available control-flow and memory-execution protections.
5. Add boundary tests around the maximum accepted request-target length.

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
