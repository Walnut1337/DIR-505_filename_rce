#!/usr/bin/env python3
"""极简 TFTP 客户端（octet 模式）— 用于验证 tftpd 未授权文件通道
用法:
  ./tftp_client.py get <server> <remote_file> <local_file> [port]
  ./tftp_client.py put <server> <local_file> <remote_file> [port]
  (port 默认 69; NAT 场景可指定映射端口, 如 6969)
"""
import socket, struct, sys, os

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERR = 1, 2, 3, 4, 5
BLKSZ = 512

def _recv_pkt(s, expect_from=None):
    data, addr = s.recvfrom(2048)
    op = struct.unpack("!H", data[:2])[0]
    return op, data, addr

def _fname(remote):
    if remote.startswith("hex:"):
        return bytes.fromhex(remote[4:])
    return remote.encode()

def get(server, remote, local, port=69, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    req = struct.pack("!H", OP_RRQ) + _fname(remote) + b"\x00octet\x00"
    s.sendto(req, (server, port))
    op, data, addr = _recv_pkt(s)
    if op == OP_ERR:
        print("[!] server error:", data[4:-1].decode(errors="replace")); return False
    out = b""
    while True:
        block = struct.unpack("!H", data[2:4])[0]
        payload = data[4:]
        out += payload
        s.sendto(struct.pack("!HH", OP_ACK, block), addr)
        if len(payload) < BLKSZ:
            break
        op, data, addr = _recv_pkt(s)
        if op != OP_DATA:
            print("[!] unexpected op", op); return False
    open(local, "wb").write(out)
    print(f"[+] GET {remote} -> {local} ({len(out)} bytes)")
    return True

def put(server, local, remote, port=69, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    req = struct.pack("!H", OP_WRQ) + _fname(remote) + b"\x00octet\x00"
    s.sendto(req, (server, port))
    op, data, addr = _recv_pkt(s)
    if op == OP_ERR:
        print("[!] server error:", data[4:-1].decode(errors="replace")); return False
    if op != OP_ACK or struct.unpack("!H", data[2:4])[0] != 0:
        print("[!] no ACK0, got op", op); return False
    content = open(local, "rb").read()
    blk = 1; off = 0
    while True:
        chunk = content[off:off+BLKSZ]
        s.sendto(struct.pack("!HH", OP_DATA, blk) + chunk, addr)
        op, data, addr2 = _recv_pkt(s)
        if op == OP_ERR:
            print("[!] server error:", data[4:-1].decode(errors="replace")); return False
        ack = struct.unpack("!H", data[2:4])[0]
        if ack != blk:
            print("[!] bad ack", ack); return False
        off += len(chunk); blk = (blk + 1) & 0xffff
        if len(chunk) < BLKSZ:
            break
    print(f"[+] PUT {local} -> {remote} ({len(content)} bytes)")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 5 or sys.argv[1] not in ("get", "put"):
        print(__doc__); sys.exit(1)
    mode, server, a, b = sys.argv[1:5]
    port = int(sys.argv[5]) if len(sys.argv) > 5 else 69
    if mode == "get":
        ok = get(server, a, b, port)
    else:
        ok = put(server, a, b, port)
    sys.exit(0 if ok else 2)
