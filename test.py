#!/usr/bin/env python3
import sys
import time
import struct
import argparse
import os
import tempfile
import usb.core
import usb.util

try:
    import readline
except ImportError:
    pass

VID = 0x0482
PID_TARGET = 0x0A8D
DIAG_SUBSYS_CMD_F = 0x4B
KDIAG_SUBSYS_ID = 0xFC
CMD_SHELL = 0x2081
CMD_REBOOT = 0x2012
CMD_BLOCKDEV = 0x2000
CMD_WRITE_FACTORY_MODE = 0x20C0
CMD_READ_FACTORY_MODE = 0x20C1
FACTORY_PERMISSIVE = 0x04

SUBCMD_OPEN = 0x0000
SUBCMD_WRITE = 0x0003
SUBCMD_CLOSE = 0x0001
O_WRONLY = 0x0001
O_CREAT = 0x0040
O_TRUNC = 0x0200

HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_XOR = 0x20

def crc16(data):
    crc = 0xFFFF
    for b in data:
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (b ^ crc) & 1 else crc >> 1
            b >>= 1
    return (~crc) & 0xFFFF

def hdlc_encode(payload):
    data = payload + struct.pack("<H", crc16(payload))
    frame = bytearray()
    for b in data:
        if b in (HDLC_FLAG, HDLC_ESC):
            frame.extend([HDLC_ESC, b ^ HDLC_XOR])
        else:
            frame.append(b)
    frame.append(HDLC_FLAG)
    return bytes(frame)

def hdlc_decode(frame):
    raw = frame[:-1] if frame.endswith(bytes([HDLC_FLAG])) else frame
    data = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == HDLC_ESC and i + 1 < len(raw):
            data.append(raw[i + 1] ^ HDLC_XOR)
            i += 2
        else:
            data.append(raw[i])
            i += 1
    if len(data) < 3:
        return None
    payload, rx_crc = data[:-2], struct.unpack("<H", data[-2:])[0]
    return bytes(payload) if crc16(payload) == rx_crc else None

def diag_header(cmd):
    return bytes([DIAG_SUBSYS_CMD_F, KDIAG_SUBSYS_ID, cmd & 0xFF, (cmd >> 8) & 0xFF])

def blockdev_header(subcmd):
    return struct.pack(
        "<BBBBH",
        DIAG_SUBSYS_CMD_F, KDIAG_SUBSYS_ID,
        CMD_BLOCKDEV & 0xFF, (CMD_BLOCKDEV >> 8) & 0xFF,
        subcmd,
    )

def transact(ep_out, ep_in, pkt, match_len=4, timeout=5.0):
    header = pkt[:match_len]
    ep_out.write(hdlc_encode(pkt))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw = ep_in.read(16384, timeout=500)
        except usb.core.USBTimeoutError:
            continue
        payload = hdlc_decode(bytes(raw))
        if payload and payload[:match_len] == header:
            return payload
    return None

def find_best_interface():
    dev = usb.core.find(idVendor=VID, idProduct=PID_TARGET)
    if not dev:
        return None, None, None, None
    cfg = dev.get_active_configuration()
    candidates = []
    for intf in cfg:
        ep_out = None
        ep_in = None
        for ep in intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT and (ep.bmAttributes & 0x03) == 0x02:
                ep_out = ep
            elif usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN and (ep.bmAttributes & 0x03) == 0x02:
                ep_in = ep
        if ep_out and ep_in and intf.bInterfaceSubClass != 0x42:
            candidates.append((intf.bInterfaceNumber, ep_out, ep_in))
    if not candidates:
        return None, None, None, None
    for intf_num, ep_out, ep_in in candidates:
        try:
            claim_interface(dev, intf_num)
            ok, _ = read_factory_flag(ep_out, ep_in)
            release_interface(dev, intf_num)
            if ok:
                return dev, intf_num, ep_out, ep_in
        except:
            release_interface(dev, intf_num)
            continue
    intf_num, ep_out, ep_in = candidates[0]
    return dev, intf_num, ep_out, ep_in

def claim_interface(dev, intf_num):
    try:
        if dev.is_kernel_driver_active(intf_num):
            dev.detach_kernel_driver(intf_num)
    except:
        pass
    usb.util.claim_interface(dev, intf_num)

def release_interface(dev, intf_num):
    try:
        usb.util.release_interface(dev, intf_num)
    except:
        pass

def diag_exec_shell(ep_out, ep_in, cmd, timeout=10.0, debug=False):
    pkt = diag_header(CMD_SHELL) + cmd.encode() + b"\x00"
    header = pkt[:4]
    ep_out.write(hdlc_encode(pkt))
    chunks = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw = ep_in.read(16384, timeout=500)
        except usb.core.USBTimeoutError:
            if chunks:
                break
            continue
        payload = hdlc_decode(bytes(raw))
        if debug and payload:
            print(f"[DEBUG] payload: {payload.hex()}")
        if not payload or not payload.startswith(header):
            continue
        if len(payload) < 9:
            continue
        chunk = payload[9:].rstrip(b"\x00").decode("ascii", errors="replace")
        chunks.append(chunk)
        if payload[8] == 1:
            break
    return "".join(chunks)

def read_factory_flag(ep_out, ep_in):
    pkt = diag_header(CMD_READ_FACTORY_MODE)
    payload = transact(ep_out, ep_in, pkt, timeout=2.0)
    if payload and len(payload) >= 10:
        status = struct.unpack_from("<H", payload, 4)[0]
        flags = struct.unpack_from("<I", payload, 6)[0]
        return status == 0, flags
    return False, 0

def write_factory_flag(ep_out, ep_in, flags, retry=3):
    for i in range(retry):
        pkt = diag_header(CMD_WRITE_FACTORY_MODE) + struct.pack("<BBBB", flags, 0, 0, 0)
        payload = transact(ep_out, ep_in, pkt, timeout=2.0)
        if payload and len(payload) >= 6:
            status = struct.unpack_from("<H", payload, 4)[0]
            if status == 0:
                return True
        time.sleep(0.3)
    return False

def blockdev_write_path(ep_out, ep_in, path, data):
    fd = blockdev_open(ep_out, ep_in, path)
    if fd is None:
        return False
    ok = blockdev_write(ep_out, ep_in, fd, data)
    blockdev_close(ep_out, ep_in, fd)
    return ok

def blockdev_open(ep_out, ep_in, path, flags=O_WRONLY | O_CREAT | O_TRUNC):
    pkt = blockdev_header(SUBCMD_OPEN) + struct.pack("<IHH", flags, 0o644, 0) + path.encode() + b"\x00"
    resp = transact(ep_out, ep_in, pkt, match_len=6, timeout=3.0)
    if not resp or len(resp) < 16:
        return None
    status = struct.unpack_from("<H", resp, 6)[0]
    fd = struct.unpack_from("<I", resp, 8)[0]
    return fd if status == 0 and fd <= 4 else None

def blockdev_close(ep_out, ep_in, fd):
    pkt = blockdev_header(SUBCMD_CLOSE) + struct.pack("<I", fd)
    resp = transact(ep_out, ep_in, pkt, match_len=6, timeout=2.0)
    return resp is not None and struct.unpack_from("<H", resp, 6)[0] == 0

def blockdev_write(ep_out, ep_in, fd, data):
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 1024]
        pkt = blockdev_header(SUBCMD_WRITE) + struct.pack("<II", fd, len(chunk)) + chunk
        resp = transact(ep_out, ep_in, pkt, match_len=6, timeout=3.0)
        if not resp or len(resp) < 16:
            return False
        if struct.unpack_from("<H", resp, 6)[0] != 0:
            return False
        written = struct.unpack_from("<i", resp, 8)[0]
        if written < 0:
            return False
        offset += written
    return True

def diag_reboot(ep_out):
    try:
        ep_out.write(hdlc_encode(diag_header(CMD_REBOOT)))
    except usb.core.USBError:
        pass

class DiagShell:
    def __init__(self, ep_out, ep_in, debug=False):
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.debug = debug
        self.cwd = "/"

    def _send_cd(self, path):
        cmd = f"cd '{path}'"
        return diag_exec_shell(self.ep_out, self.ep_in, cmd, timeout=5.0, debug=self.debug)

    def _normalize(self, target):
        if target.startswith("/"):
            new = target
        elif target == "..":
            new = os.path.dirname(self.cwd.rstrip("/")) or "/"
        elif target == "." or target == "~":
            new = self.cwd
        else:
            new = os.path.join(self.cwd, target)
        return os.path.normpath(new)

    def execute(self, raw_cmd):
        cmd = raw_cmd.strip()
        if not cmd:
            return ""

        if cmd.startswith("cd "):
            target = cmd[3:].strip()
            if not target:
                target = "/"
            new_path = self._normalize(target)
            err = self._send_cd(new_path)
            if err:
                return err
            self.cwd = new_path
            return ""

        if cmd == "pwd":
            return self.cwd

        if self.cwd and self.cwd != "/":
            wrapped = f"cd '{self.cwd}' && {cmd}"
        else:
            wrapped = cmd
        return diag_exec_shell(self.ep_out, self.ep_in, wrapped, timeout=10.0, debug=self.debug)

    def run_script(self, script_content):
        lines = [line.strip() for line in script_content.splitlines() if line.strip()]
        if not lines:
            return ""
        prefixed = []
        for line in lines:
            if line.startswith("cd "):
                prefixed.append(line)
            else:
                if self.cwd and self.cwd != "/":
                    prefixed.append(f"cd '{self.cwd}' && {line}")
                else:
                    prefixed.append(line)
        combined = " && ".join(prefixed)
        return diag_exec_shell(self.ep_out, self.ep_in, combined, timeout=30.0, debug=self.debug)

    def interactive(self):
        print("\n[DIAG シェル] ")
        print(f"  現在のディレクトリ: {self.cwd}")
        print("  終了: Ctrl+C または 'exit'")
        print()
        while True:
            try:
                prompt = f"diag:{self.cwd}$ "
                cmd = input(prompt).strip()
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n中断されました。")
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            if cmd.startswith("source ") or cmd.startswith(". "):
                fname = cmd.split(maxsplit=1)[1]
                try:
                    with open(fname, "r") as f:
                        content = f.read()
                    print(f"[実行] {fname} のスクリプトを実行中...")
                    out = self.run_script(content)
                    if out:
                        print(out.rstrip())
                    else:
                        print("(スクリプト実行完了 - 出力なし)")
                except FileNotFoundError:
                    print(f"ファイル '{fname}' が見つかりません。")
                continue
            if cmd == "clear":
                print("\033[H\033[J", end="")
                continue
            try:
                out = self.execute(cmd)
                if out:
                    print(out.rstrip())
                else:
                    if not cmd.startswith("cd "):
                        print("(実行完了 - 出力なし)")
                if cmd.startswith("cd "):
                    print(f"現在: {self.cwd}")
            except usb.core.USBError as e:
                print(f"[!] USBエラー: {e}")
                break
            except Exception as e:
                print(f"[!] エラー: {e}")
                break

def main():
    parser = argparse.ArgumentParser(description="Kyocera DIAG シェル ")
    parser.add_argument("--shell", action="store_true", help="インタラクティブシェルを開く")
    args = parser.parse_args()

    print("=== Kyocera DIAG シェル ===")

    dev, intf_num, ep_out, ep_in = find_best_interface()
    if not dev:
        print("エラー: デバイスが見つかりません。")
        sys.exit(1)

    print(f"デバイス: {usb.util.get_string(dev, dev.iProduct)} (SN: {usb.util.get_string(dev, dev.iSerialNumber)})")
    print(f"インターフェース: IF#{intf_num}")

    claim_interface(dev, intf_num)

    try:
        print("\n[準備] kcpermissive (0x04) を書き込み中...")
        if write_factory_flag(ep_out, ep_in, FACTORY_PERMISSIVE):
            print("  [OK] 書き込み完了")
        else:
            print("  [警告] 書き込み失敗 (後で試せます)")
        ok, flags = read_factory_flag(ep_out, ep_in)
        if ok:
            print(f"  現在のフラグ: 0x{flags:08x} (kcpermissive: {bool(flags & 0x04)})")
        if args.shell:
            shell = DiagShell(ep_out, ep_in, debug=args.debug)
            shell.interactive()
        else:
            print("\nシェルを開くには --shell オプションを付けて再実行してください。")
            p    finally:
        release_interface(dev, intf_num)

    print("\n終了しました。")

if __name__ == "__main__":
    main()
