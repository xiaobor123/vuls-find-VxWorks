# Overview

Details of the vulnerability found in the TP-LINK router TL-WDR7651.

| Firmware Name | Firmware Version | Download Link |
| -------------- | ---------------- | ------------- |
| TL-WDR7651 | V1.0 upgrade software 20191021_2.0.6 | https://service.tp-link.com.cn/detail_download_7974.html |

Product page:

```text
https://www.tp-link.com.cn/product_1480.html
```

![Product Proof](./assets/image1.png)

# Vulnerability details

## 1. Vulnerability trigger Location

A stack overflow vulnerability exists in the call chain of `devDiscoverHandle` within the firmware. The triggering path is:

```text
devDiscoverHandle -> protocol_handler -> ms_idle_handler -> parse_advertisement_frame -> copy_msg_element
```

In the `copy_msg_element` function, `memcpy` is called without proper boundary checks. A specially crafted UDP packet can trigger this vulnerability.

Relevant symbols:

| Function | Address |
| --- | --- |
| `memcpy` | `0x402904A8` |
| `devDiscoverHandle` | `0x40560EA4` |
| `parse_msg_element` | `0x40562AF8` |
| `copy_msg_element` | `0x40562DA0` |
| `parse_advertisement_frame` | `0x40562DE8` |
| `ms_idle_handler` | `0x40564514` |
| `protocol_handler` | `0x40564814` |

The vulnerable copy site was observed around `0x40562DD4` during reverse analysis.

![Vulnerability Trigger Location](./assets/image2.png)
![Related Code](./assets/image3.png)

## 2. Vulnerability Analysis

- During protocol parsing, the program reads a length field fully controlled by the user from the network packet. After `parse_msg_element` locates the corresponding element, this length is passed directly to `copy_msg_element` and ultimately used in `memcpy(a2, a1 + 4, a3)`.
- The destination buffer is fixed-size on the stack, about `229` bytes. Because there is no bounds checking between the user-controlled length and the size of the destination buffer, an attacker can craft a well-formed element with an excessively large length value. This causes `memcpy` to write beyond the stack buffer, overwriting adjacent memory and potentially the return address, leading to a crash or even arbitrary code execution.

![Analysis 1](./assets/image4.png)
![Analysis 2](./assets/image5.png)

# POC

## python script

```python
import socket
from time import sleep

TARGET_IP = "192.168.3.28"
TARGET_PORT = 5001


def send_payload(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"[*] Loaded payload: {len(data)} bytes")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.sendto(data, (TARGET_IP, TARGET_PORT))
    udp.close()

    print("[+] Payload sent")


if __name__ == "__main__":
    send_payload("payload.txt")
    sleep(1)
```

# Vulnerability Verification Screenshot

## wdr7651

- Use `binwalk -Me` to extract the `10400` file from the original firmware. The firmware's operating system is VxWorks, and this file is the main binary. The symbol table file was also used during analysis. Then, we used a self-developed emulation tool specifically designed for VxWorks to start the service and perform validation.

![Verification 1](./assets/image6.png)
![Verification 2](./assets/image7.png)
![Verification 3](./assets/image8.png)

# Discoverer

m202472188@hust.edu.cn HUST IOTS&P lab
