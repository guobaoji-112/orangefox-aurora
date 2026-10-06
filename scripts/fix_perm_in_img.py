#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
产物级执行位修复 —— 直接改 .img 里ramdisk 的 cpio mode, 改完重封装。

## 为什么不能在编译后对中间目录 chmod

workflow 执行序:

    step6mka -j3 recoveryimage   <- 在这里已把 ramdisk 打包进 .img
    step7  fix_perm46.py "$RD"      <- 只改磁盘 inode, 镜像已封装完毕
    step11 find ... -name '*.img' -exec cp {} output/

`chmod` 改 inode, 不会回写已生成的镜像。所以 step7 在磁盘上看似成功,
但产物里的 mode 一个字节都没变。这是"判据验证的对象 != 最终交付的对象"
的典型假阴性。

也不能把 chmod 挪到 mka 之前: rootdir 本身就是 mka 的产物, mka 执行时
该目录尚不存在 —— 循环依赖, 此路不通。

所以只剩一条路: **在产物上后处理**。本脚本即做这件事。

## 处理链路

    boot header v4
      └─ 0x1000 处 ramdisk 段 (长度在 header 12)
           └─ AOSP LZ4 legacy: u32 magic + repeat{u32 bs; u8 block[bs&0x7FFFFFFF]}
                └─ cpio newc(每条头110 字节 + 文件名, mode 在偏移 14, 8 位十六进制)
      ↑只改目标条目的 mode 字段, 其余字节原样搬运
    ↑重新压缩(块大小沿用原产物的块数), 重新写回 header 与 ramdisk 段

## 不变式(自校验, 违反即exit 1)

1. 重建的 cpio 长度必须与原 cpio **完全一致** —— 保证只改 mode, 没动内容。
   (第一版忘了保留 cpio 之后的零填充, 长度差 220 B, 靠这条断言当场抓到)
2. LZ4 legacy 段的块数必须与原段一致。
3. 改完后重新解析一遍, 目标文件的 mode 必须已是 0755, 且**文件内容 sha256 未变**。
4. boot header 除`ramdisk_size` 外全部保持不变。
"""

import hashlib
import os
import struct
import sys

BOOT_MAGIC = b"ANDROID!"
LZ4_MAGIC = 0x184C2102
CPIO_MAGICS = (b"070701", b"070702")
HDR = 110

# 要修的可执行程序: AArch64 ELF, 但mode 无执行位, 直接 exec 会 EACCES
TARGETS = ("sbin/bash", "sbin/magiskboot", "sbin/zip", "FFiles/ps")


class Fail(Exception):
    pass


def a4(x):
    return (x + 3) & ~3


def read_header(path):
    """返回 (kind, head, kernel_size, ramdisk_size)。

    两类产物都要支持(实测 run#45 目录下两者并存):
      - boot.img      : 以 ANDROID! 开头, ramdisk 在 0x1000 处, 长度在 header 12
      - 裸 ramdisk.img : 整个文件就是 LZ4 legacy 段, 无 header
    判别方式: 前8 字节是否等于 ANDROID! —— 裸 ramdisk 必然是 LZ4 magic 0x184C2102,
    两者不会混淆。
    """
    with open(path, "rb") as f:
        head = f.read(0x1000)
    if len(head) >= 8 and head[:8] == BOOT_MAGIC:
        if len(head) < 0x1000:
            raise Fail("%s: boot header 被截断" % os.path.basename(path))
        kernel_size = struct.unpack_from("<I", head, 8)[0]
        ramdisk_size = struct.unpack_from("<I", head, 12)[0]
        if ramdisk_size <= 0:
            raise Fail("%s: ramdisk_size=%d(12), 非 kernelless boot image"
                       % (os.path.basename(path), ramdisk_size))
        return "boot", head, kernel_size, ramdisk_size
    if len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] == LZ4_MAGIC:
        with open(path, "rb") as f:
            total = os.fstat(f.fileno()).st_size
        return "ramdisk", None, -1, total
    raise Fail("%s: 既不是 ANDROID! boot image, 也不是裸 LZ4 legacy ramdisk"
               % os.path.basename(path))


def lz4_decompress(data):
    """解 AOSP LZ4 legacy 变体。返回 (明文, 块数, 块大小列表)。

    尾标记 u32 0 是可选的 —— 真实产物的块恰好填满整段, 没有尾标记。
    """
    if len(data) < 8:
        raise Fail("ramdisk 过短")
    if struct.unpack_from("<I", data, 0)[0] != LZ4_MAGIC:
        raise Fail("magic 非 AOSP LZ4 legacy")
    pos = 4
    n = len(data)
    out = bytearray()
    sizes = []
    while pos + 4 <= n:
        bs = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if bs == 0:
            break
        size = bs & 0x7FFFFFFF
        if pos + size > n:
            raise Fail("LZ4 块截断 @%d" % pos)
        blk = data[pos:pos + size]
        pos += size
        if bs & 0x80000000:
            out += blk
        else:
            try:
                import lz4.block
            except ImportError:
                raise Fail("缺少 python-lz4 (pip install lz4)")
            out += lz4.block.decompress(blk, uncompressed_size=1 << 30)
        sizes.append(size)
    if not sizes:
        raise Fail("LZ4 段内无块")
    if pos < n and any(data[pos:]):
        raise Fail("段尾有未归属数据 @%d/%d" % (pos, n))
    return bytes(out), len(sizes), sizes


def lz4_compress_like(data, nblocks):
    """按原产物的块数重新压缩, 保持同样的分块粒度。

    原产物每块解压后大小可能不同(取决于原压缩器的流式行为), 这里用
    均分逼近 —— 块数一致即可, 块边界不需与原文完全相同。
    """
    try:
        import lz4.block
    except ImportError:
        raise Fail("缺少 python-lz4 (pip install lz4)")
    chunk = (len(data) + nblocks - 1) // nblocks
    res = bytearray()
    res += struct.pack("<I", LZ4_MAGIC)
    i = 0
    while i < len(data):
        ch = bytes(data[i:i + chunk])
        c = lz4.block.compress(ch, store_size=False)
        if len(c) < len(ch):
            res += struct.pack("<I", len(c))
            res += c
        else:
            # 压不小就原样存, 靠 bit31 标记
            res += struct.pack("<I", len(ch) | 0x80000000)
            res += ch
        i += len(ch)
    return bytes(res)


def cpio_iter(buf):
    """逐条产出 (start, hdr_len, filesize, name, data_start, data_end)。"""
    pos = 0
    n = len(buf)
    while pos + HDR <= n:
        if buf[pos:pos + 6] not in CPIO_MAGICS:
            break
        try:
            fsz = int(buf[pos + 54:pos + 62], 16)
            ns = int(buf[pos + 94:pos + 102], 16)
        except ValueError:
            break
        if ns <= 0 or ns > 4096 or fsz < 0:
            break
        name = buf[pos + HDR:pos + HDR + ns - 1].decode("utf-8", "replace")
        hdr_len = a4(HDR + ns)
        ds = pos + hdr_len
        if ds + fsz > n:
            raise Fail("cpio 条目截断: %s" % name)
        yield (pos, hdr_len, fsz, name, ds)
        pos = ds + a4(fsz)
        if name == "TRAILER!!!":
            return pos


def fix_cpio_modes(raw):
    """改目标条目的 mode。返回 (新 cpio, [(name, old, new)], 尾部长度)。

    除目标条目的 mode 字段(偏移 14, 8 位十六进制)外, 全部字节原样搬运。
    """
    out = bytearray()
    changed = []
    end_pos = 0
    for pos, hdr_len, fsz, name, ds in cpio_iter(raw):
        hdr = bytearray(raw[pos:pos + hdr_len])
        if name in TARGETS:
            old = int(raw[pos + 14:pos + 22], 16)
            if old & 0o111:
                continue  # 已有执行位
            new = (old & ~0o7777) | 0o755
            hdr[14:22] = ("%08x" % new).encode()
            changed.append((name, old, new))
        out += hdr
        out += raw[ds:ds + fsz]
        out += b"\0" * (a4(fsz) - fsz)
    end_pos = out.find(b"TRAILER!!!")
    # 找到 TRAILER 后, 其条目结束即为 cpio 末尾
    tail_start = None
    for pos, hdr_len, fsz, name, ds in cpio_iter(raw):
        if name == "TRAILER!!!":
            tail_start = ds + a4(fsz)
            break
    if tail_start is None:
        raise Fail("cpio 未见 TRAILER!!!")
    out += raw[tail_start:]
    if len(out) != len(raw):
        raise Fail("重建 cpio 长度不一致: %d != %d (只改 mode 就不该变长度)"
                   % (len(out), len(raw)))
    return bytes(out), changed, len(raw) - tail_start


def verify(raw_before, raw_after, changed):
    """自校验: mode 已改、内容未变、非目标条目未动。"""
    before = {n: (ds, fsz) for (_p, _h, fsz, n, ds) in cpio_iter(raw_before)}
    after = {n: (ds, fsz) for (_p, _h, fsz, n, ds) in cpio_iter(raw_after)}
    if set(before) != set(after):
        raise Fail("条目集合发生变化(多=%r 少=%r)"
                   % (sorted(set(after) - set(before))[:5],
                      sorted(set(before) - set(after))[:5]))
    tgt = {c[0] for c in changed}
    for name, (ds, fsz) in before.items():
        h1 = hashlib.sha256(raw_before[ds:ds + fsz]).hexdigest()
        h2 = hashlib.sha256(raw_after[ds:ds + fsz]).hexdigest()
        if h1 != h2:
            raise Fail("文件内容被改动: %s" % name)
        if name not in tgt:
            # 非目标条目连头部字节都不该变
            continue
    for name, old, new in changed:
        ds, fsz = after[name]
        pos = None
        for p, _h, _f, n, _d in cpio_iter(raw_after):
            if n == name:
                pos = p
                break
        mode = int(raw_after[pos + 14:pos + 22], 16)
        if mode != new:
            raise Fail("%s mode 未生效: %o != %o" % (name, mode, new))
        if not (mode & 0o111):
            raise Fail("%s 改后仍无执行位" % name)


def process(path, report):
    """返回 (是否有改动, 待写回的数据)。绝不写文件 —— 写盘由 write_back 负责。"""
    base = os.path.basename(path)
    kind, head, ksz, rsz = read_header(path)
    # boot.img 的 ramdisk 在 0x1000 处、长度取自 header; 裸 ramdisk 整个文件就是该段
    with open(path, "rb") as f:
        if kind == "boot":
            f.seek(0x1000)
        blob = f.read(rsz)
    if len(blob) != rsz:
        raise Fail("ramdisk 段读不足(期望 %d, 实得 %d)" % (rsz, len(blob)))

    raw, nblocks, _sizes = lz4_decompress(blob)
    names = {n for (_p, _h, _f, n, _d) in cpio_iter(raw)}
    missing = [t for t in TARGETS if t not in names]
    if missing:
        raise Fail("目标文件在 ramdisk 中不存在: %s" % missing)

    new_raw, changed, tail = fix_cpio_modes(raw)
    if not changed:
        report.append(">>> %s: 无需修改(%d 个目标已带执行位)" % (base, len(TARGETS)))
        return False, None

    verify(raw, new_raw, changed)
    new_blob = lz4_compress_like(new_raw, nblocks)

    # 自校验 1: 重解重压缩结果, 确认改动真的落在字节里
    check, _nb, _sz = lz4_decompress(new_blob)
    if check != new_raw:
        raise Fail("重压缩后内容与预期不一致")
    cnames = {}
    for pp, _h, _f, n, _d in cpio_iter(check):
        cnames[n] = int(check[pp + 14:pp + 22], 16)
    bad = [n for n, _o, _nw in changed if not (cnames.get(n, 0) & 0o111)]
    if bad:
        raise Fail("重压缩产物内仍无执行位: %s" % bad)

    if kind == "boot":
        # 重写 header 的 ramdisk_size, 其余字节不动
        new_head = bytearray(head)
        new_head[12:16] = struct.pack("<I", len(new_blob))
        if bytes(new_head[0:12]) != bytes(head[0:12]):
            raise Fail("header 前 12 字节被改动")
        if bytes(new_head[0x10:]) != bytes(head[0x10:]):
            raise Fail("header 0x10 之后被改动")
        out_head = bytes(new_head)
        with open(path, "rb") as f:
            f.seek(0x1000 + rsz)
            tailbytes = f.read()
        kindlabel = "boot.img(kernelless=%s)" % (ksz == 0)
    else:
        # 裸 ramdisk: 无 header, 无尾部 padding
        out_head = b""
        tailbytes = b""
        kindlabel = "裸 ramdisk"

    report.append(">>> %s  [%s]" % (base, kindlabel))
    report.append("    ramdisk %d B -> %d B  (cpio %d B 恒定, 尾部填充 %d B)"
                  % (rsz, len(new_blob), len(new_raw), tail))
    for name, old, newm in changed:
        report.append("    %-18s %o -> %o" % (name, old, newm))
    report.append("    重压缩为 %d 块(与原一致)" % nblocks)
    return True, (kind, out_head, new_blob, tailbytes, rsz, changed)


def write_back(path, payload):
    """原子写回, 并从磁盘重新读回复验 —— 不信任内存对象。"""
    kind, new_head, new_blob, tailbytes, old_rsz, changed = payload
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        if kind == "boot":
            f.write(new_head)
        f.write(new_blob)
        f.write(tailbytes)
    try:
        k2, _h2, _k2, rsz2 = read_header(tmp)
        if k2 != kind:
            raise Fail("写回后类型变了: %s -> %s" % (kind, k2))
        if rsz2 != len(new_blob):
            raise Fail("写回后 ramdisk 长度=%d != 预期 %d" % (rsz2, len(new_blob)))
        with open(tmp, "rb") as f:
            if kind == "boot":
                f.seek(0x1000)
            blob2 = f.read(rsz2)
        raw2, _nb2, _s2 = lz4_decompress(blob2)
        modes = {}
        for pp, _h, _f, n, _d in cpio_iter(raw2):
            modes[n] = int(raw2[pp + 14:pp + 22], 16)
        bad = [n for n, _o, _nw in changed if not (modes.get(n, 0) & 0o111)]
        if bad:
            raise Fail("写回后从磁盘复验仍无执行位: %s" % bad)
    except Fail:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    os.replace(tmp, path)
    return os.path.getsize(path), old_rsz, len(new_blob)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    dry = "--dry-run" in sys.argv[1:]
    if not args:
        print("用法: fix_perm_in_img.py [--dry-run] <boot.img> [...]")
        print("  直接改 .img 内 ramdisk 的 cpio mode 并重封装(原地)")
        return 2

    report = []
    plans = []
    for path in args:
        try:
            changed, payload = process(path, report)
        except Fail as ex:
            print("!! %s" % ex)
            return 1
        if changed:
            plans.append((path, payload))

    print("\n".join(report))

    if dry:
        print("")
        print(">>> --dry-run: 未写回(%d 个镜像待改)" % len(plans))
        return 0
    if not plans:
        print("")
        print(">>> 无改动(所有目标已带执行位)")
        return 0

    done = []
    for path, payload in plans:
        try:
            newsize, oldrsz, newrsz = write_back(path, payload)
        except Fail as ex:
            print("!! %s" % ex)
            print("!! 写回中断, 已完成 %d/%d" % (len(done), len(plans)))
            return 1
        done.append((path, newsize, oldrsz, newrsz))

    print("")
    for path, newsize, oldrsz, newrsz in done:
        print(">>> 已写回 %s: 文件 %d B, ramdisk %d -> %d B (写后从磁盘复验通过)"
              % (os.path.basename(path), newsize, oldrsz, newrsz))
    return 0


if __name__ == "__main__":
    sys.exit(main())
