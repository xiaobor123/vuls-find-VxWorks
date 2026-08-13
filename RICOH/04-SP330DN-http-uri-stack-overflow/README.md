# RICOH SP 330DN HTTP Request-Target Stack Buffer Overflow

## Summary

The analyzed RICOH SP 330DN firmware copies an attacker-controlled HTTP request target into a fixed-size stack buffer without an adequate length check. A sufficiently long URI overwrites the saved return address. Dynamic reproduction with a repeated `B` pattern changed the program counter to `0x42424242`, demonstrating input-controlled control-flow corruption.

## Vulnerability information

| Field | Value |
|---|---|
| Report ID | RICOH-04 |
| Vendor | RICOH Company, Ltd. |
| Product | RICOH SP 330DN |
| Analyzed image | `20030_SP330DN` |
| Firmware version (analyzed image) | `V1.11` |
| Firmware SHA-256 | `764771134ca39b2d334ce94592768c8931d4415e64d39b3a4e5899e020af7868` |
| Vendor product page | [RICOH SP 330DN downloads](https://support.ricoh.com/bb/html/dr_ut_e/apc/model/sp330dn/sp330dnen.htm) |
| Legacy firmware availability | The analyzed `V1.11` package is no longer listed on the vendor's public download page. |
| Affected component | HTTP resource-request processing |
| Vulnerability type | Stack-based buffer overflow |
| CWE | CWE-121: Stack-based Buffer Overflow |
| Attack vector | Network, if the HTTP service is reachable |

The vendor product page currently provides a newer firmware release and is included as the authoritative product reference, not as a download link for the analyzed legacy package. The exact analyzed sample is identified by its embedded `V1.11` version string and the SHA-256 digest above.

## Test files

- [Analyzed firmware image: `20030_SP330DN`](./firmware/20030_SP330DN)  
  SHA-256: `764771134ca39b2d334ce94592768c8931d4415e64d39b3a4e5899e020af7868`
- [Recovered symbol table: `symbols.txt`](./firmware/symbols.txt)  
  SHA-256: `0d59bf0b9d590c3d945bdd24aa93eb9043df2645ced9073d877400fbc7bb4373`

The symbol table contains the recovered function-name-to-address mapping used during analysis and rehosting. It is not an original vendor debug-symbol package.

## Technical details

The affected HTTP resource-processing function begins near `0x5F5708`. At `0x5F5E9C`, the function calls `strcpy` with the parsed HTTP request target as the source and a local stack address as the destination. The implementation does not validate that the request target fits in the destination buffer.

A simplified representation is:

```c
int fetch_http_resource(const char *request_target) {
    char local_path[FIXED_SIZE];
    strcpy(local_path, request_target);  /* unbounded copy */
    return process_path(local_path);
}
```

When the function restores its saved execution state, bytes from the request target are used as the return address.

## Reproduction

The included [`poc.py`](./poc.py) generates a valid HTTP GET request containing a long request target. By default, it writes `payload.bin` and does not contact a network target.

```bash
python3 poc.py
python3 poc.py --host <target> --port 80 --length 640 --byte B --send
```

Use only against an authorized device or rehosting instance. The default length reproduces the overwrite in the analyzed environment; physical-device request limits and authentication requirements remain to be confirmed.

## Observed result

The rehosting environment accepted a GET request containing 640 repeated `B` bytes in the request target. After the vulnerable function processed the path and attempted to return, the emulator reported:

```text
PC 0x42424242 outside execution range 0x0..=0x1000000
qemu.run() returned: Ok(Crash)
QEMU requested crash
```

Because the faulting PC exactly matches the attacker-supplied byte pattern, the result demonstrates control of the saved return address rather than a fixed exception vector or task-exit sentinel.

Relevant artifacts:

- [Generated proof-of-concept payload](./payload.bin)
- [Replay excerpt showing PC 0x42424242](./evidence/SP330_long_uri_B_excerpt.txt)
- [Evidence manifest](./evidence/manifest.json)

## Security impact

At minimum, a remote request can crash the HTTP service or its request-processing task. Input control over the saved return address means arbitrary code execution may be possible where platform protections are absent or bypassable. This report proves program-counter control but does not claim a complete code-execution exploit.

## Remediation

1. Enforce a strict maximum request-target length before copying or decoding it.
2. Replace `strcpy` with a bounded operation that receives the actual destination capacity.
3. Repeat the length check after URL decoding and path canonicalization.
4. Enable available stack-protection and non-executable-memory mitigations.
5. Add tests at, below, and above the maximum accepted request-target length.

## Reporter

HUST IOTS&P Lab  
Contact: `m202472188@hust.edu.cn`
