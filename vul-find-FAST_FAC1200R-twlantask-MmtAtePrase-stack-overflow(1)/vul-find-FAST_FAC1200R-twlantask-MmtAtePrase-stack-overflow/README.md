# Overview

Details of the vulnerability found in the FAST FAC1200R router firmware.

| Firmware Name | Version | Download Link |
|--------------|---------|---------------|
| FAC1200R | V5.0_20201119_1.0.2 | https://service.fastcom.com.cn/download-388.html |

# Vulnerability Details

## 1. Vulnerability Trigger Location

A stack-based buffer overflow risk exists in the `MmtAtePrase` parsing path reached from the firmware's UDP 1060 `twlantask` service. A crafted UDP packet with the `wioctl` command prefix and an oversized argument can enter the vulnerable parser.

The payload used during validation is:

```text
"wioctl" + 3065 space characters + "\n"
```

The total payload length is `3072` bytes.

## 2. Vulnerability Analysis

The vulnerable path processes a network-controlled `wioctl` argument inside a stack-based parser. The parser uses a local stack buffer and does not enforce a sufficient upper-bound check before handling the oversized argument. This can corrupt stack data and cause service crash or denial of service.

The validation materials include:

```text
FAC1200R_twlantask_MmtAtePrase_stack_overflow_report.docx
verification_video.mp4
FAST_FAC1200R/10400
FAST_FAC1200R/symbols.txt
FAST_FAC1200R/payload.txt
record_twlantask_mmtate_stack_overflow.sh
assets/
```

# Vulnerability Trigger Process

1. Extract the firmware main binary `10400` from the FAST FAC1200R firmware.
2. Use the provided symbol file `symbols.txt` during analysis.
3. Start the local VxWorks firmware emulation environment.
4. Configure UDP port `1060` as the input source.
5. Inject the oversized `wioctl` payload.
6. Use the included validation script to confirm the vulnerable path and auxiliary crash behavior.

Run:

```bash
chmod +x ./record_twlantask_mmtate_stack_overflow.sh
./record_twlantask_mmtate_stack_overflow.sh
```

# Proof-of-Concept

Payload generation:

```bash
perl -e 'print "wioctl" . (" " x 3065) . "\n"' > payload.txt
```

# Impact

The issue can be triggered without authentication if an attacker can send packets to UDP port `1060` on the affected device. The practical impact is device service crash or denial of service. If the UDP service is reachable from a broader network segment, the exposure increases accordingly.

# Workaround

1. Restrict UDP port `1060` access to trusted hosts only.
2. Filter untrusted UDP 1060 traffic on the gateway or firewall.
3. Do not expose vendor-private management or discovery services to the WAN side.
4. Disable unnecessary remote management or discovery features if possible.

# Official Fix

No public firmware patch for this specific issue has been confirmed at this time. The vendor should add strict length checks in the `twlantask` / `MmtAtePrase` parsing path and reject oversized arguments before processing.

# Discoverer

m202472188@hust.edu.cn HUST IOTS&P lab
