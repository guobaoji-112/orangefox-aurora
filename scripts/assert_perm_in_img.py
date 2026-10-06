#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
产物级执行位断言 —— 直接检查已封装的 .img, 而不是磁盘上的中间目录。

## 为什么必须查 .img 而不是查 rootdir

run#47 教训(step7 = "修复 ramdisk 执行位") 是一个**无效修复**:
workflow 的实际执行序是

    step6  mka -j3 recoveryimage<- 在这里已经把 ramdisk 打包进 .img
    step7  fix_perm46.py "$RD"      <- 改的是磁盘文件树, 镜像早已封装完毕
    step11 find ... -name '*.img' -exec cp {} output/<- 拷走的是 step6 的产物

`chmod` 只改 inode, 不会回写已生成的 boot/ramdisk 镜像。所以 step7 在
磁盘上看似成功(4 个文件 mode 变成 0755), 但**产物里的 mode 一个字节都没变**。

这类"中间态 PASS、产物态 FAIL"是 CI 判据最典型的假阴性 —— 判据验证的对象
和最终交付的对象不是同一个。本脚本把断言锚定到唯一有意义的层级: 产物本身。

## 断言内容

对 boot header 声明的 ramdisk 段:
  1. 解出 cpio newc
  2. 找出「ELF 且无执行位」的文件, 剔除两类设计使然者:
       - .so / .ko共享库与内核模块, 按设计不需要执行位
       - firmware_mnt 下 *.mdt / .b00    固件分区数据, 按设计就是 0644
  3. 剩余集合必须为空; 非空则列出并 exit 1

## 容器格式说明(踩过的坑, 不要改)

本树 ramdisk 是 **AOSP 专用 LZ4 legacy 变体**:
    u32 magic = 0x184C2102
    repeat: u32 block_size   (bit31 set => 该块未压缩, 原样存储)
            u8  block[block_size & 0x7FFFFFFF]
    u32 0                            (结束标记)
**没有** FLG/BD/HC frame descriptor。按标准 frame 解会读出 FLG=0xe2(非法版本位)。

两个容易写错的点:
  - block_size 的 bit31 是"未压缩"标志位, 不能当长度用
  - cpio newc 头部字段是 13 个 8 字节十六进制, 第一个在偏移 6,
    文件名长度在偏移 94, 名字从偏移 110 开始

boot header v4 的 ramdisk_size 在偏移 0x0C(不是标准 0x10)。
"""

import os
import struct
import sys

BOOT_MAGIC = b"ANDROID!"
LZ4_MAGIC = 0x184C2102

# 设计上就不需要执行位的后缀
EXEMPT_SUFFIX = (".so", ".ko")
# 固件分区数据的后缀(按设计就是 0644, 是 ELF 魔数只是巧合 —— 分区镜像首部)
FIRMWARE_SUFFIX = (".mdt", ".b00")
# 固件分区数据的路径标识(任意层级, 因为 ramdisk 内是 vendor/firmware_mnt/...)
FIRMWARE_PATH_MARK = "firmware_mnt/"


class Fail(Exception):
    pass


def read_boot_ramdisk(img_path):
    """从 boot header v4 定位并读出 ramdisk 段, 返回 (ramdisk_bytes, kernel_size)。"""
    with open(img_path, "rb") as f:
        head = f.read(0x1000)
        if len(head) < 0x1000:
            raise Fail("%s: 文件小于 0x1000, 不是有效 boot image" % img_path)
        if head[:8] != BOOT_MAGIC:
            raise Fail("%s: magic=%r, 不是 ANDROID! boot image" % (img_path, head[:8]))
        kernel_size = struct.unpack_from("<I", head, 8)[0]
        # v4 header: ramdisk_size 在 0x0C
        ramdisk_size = struct.unpack_from("<I", head, 0x0C)[0]
        if ramdisk_size <= 0:
            raise Fail("%s: ramdisk_size=%d(0x0C 处), 该分区不是 kernelless boot image"
                       % (img_path, ramdisk_size))
        f.seek(0x1000)
        blob = f.read(ramdisk_size)
    if len(blob) != ramdisk_size:
        raise Fail("%s: ramdisk 段读不足(期望 %d, 实得 %d)"
                   % (img_path, ramdisk_size, len(blob)))
    return blob, kernel_size


def decompress_android_lz4(data):
    """解 AOSP LZ4 legacy 变体。返回 (解压后数据, 块统计列表)。

    **结束标记是可选的**: 实测本树真实产物(`ramdisk-recovery.img`, 47376664 B)
    的 16 个块恰好填满整个段, 尾部没有 u32 0 —— 解析器按"读完所有块即完成"
    处理。所以这里不强制要求 bs==0, 只在读到时记录; 但如果剩余字节既不是
    结束标记、也不是空, 视为截断并报错(防止静默少解一块)。
    """
    if len(data) < 8:
        raise Fail("ramdisk 过短(%d B)" % len(data))
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != LZ4_MAGIC:
        raise Fail("ramdisk magic=0x%08x, 不是 AOSP LZ4 legacy" % magic)
    pos = 4
    n = len(data)
    out = bytearray()
    blocks = []
    while pos + 4 <= n:
        bs = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if bs == 0:
            blocks.append(("END", 0, len(out)))
            # 结束标记之后允许有对齐填充, 但不允许再有有效块
            if pos < n and any(data[pos:]):
                raise Fail("LZ4 结束标记后仍有非零数据 @%d/%d" % (pos, n))
            break
        uncompressed = bool(bs & 0x80000000)
        size = bs & 0x7FFFFFFF
        if pos + size > n:
            raise Fail("LZ4 块被截断 @%d want=%d got=%d" % (pos, size, n - pos))
        blk = data[pos:pos + size]
        pos += size
        if uncompressed:
            out += blk
            blocks.append(("RAW", size, len(out)))
        else:
            try:
                import lz4.block
            except ImportError:
                raise Fail("缺少 python-lz4 依赖(pip install lz4), 不做静默降级")
            try:
                out += lz4.block.decompress(blk, uncompressed_size=1 << 30)
            except Exception as ex:
                raise Fail("LZ4 块解压失败: %s" % ex)
            blocks.append(("LZ4", size, len(out)))
    else:
        # 循环自然耗尽: 所有字节都归属某一块, 这是合法的(AOSP 不强制写尾标记)
        pass

    if not blocks:
        raise Fail("LZ4 legacy 段内无任何块")
    if pos < n and not all(b == 0 for b in data[pos:]):
        raise Fail("LZ4 段尾部有未归属的非零数据 @%d/%d: %r"
                   % (pos, n, data[pos:pos + 8].hex()))
    return bytes(out), blocks


def parse_cpio_newc(data):
    """解析 cpio newc/crc。返回 (entry 列表, 消费字节数)。"""
    entries = []
    pos = 0
    n = len(data)
    TYPES = {4: "d", 8: "f", 10: "l", 6: "b", 2: "c", 1: "p", 12: "s"}

    def hx(o):
        s = data[pos + o:pos + o + 8]
        try:
            return int(s, 16)
        except ValueError:
            return -1

    while pos + 110 <= n:
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            break
        mode = hx(14)
        filesize = hx(54)
        namesize = hx(94)
        if namesize <= 0 or namesize > 4096 or filesize < 0:
            break
        name = data[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "replace")
        hdr_len = (110 + namesize + 3) & ~3
        ds = pos + hdr_len
        if ds + filesize > n:
            raise Fail("cpio 条目数据被截断: %s (need %d, 剩余 %d)"
                       % (name, filesize, n - ds))
        ftype = TYPES.get((mode >> 12) & 0xF, "?")
        entries.append({
            "name": name, "typechar": ftype, "mode": mode,
            "filesize": filesize, "data": data[ds:ds + filesize],
        })
        pos = ds + ((filesize + 3) & ~3)
        if name == "TRAILER!!!":
            return entries, pos
    raise Fail("cpio 未见到 TRAILER!!! 终止标记")


def classify_missing_exec(entries):
    """返回 (真缺陷列表, 已豁免数量)。真缺陷 = ELF + 无执行位 + 非豁免类。

    豁免两类(都是设计使然, 不是缺陷):
      1. .so / .ko   —— 共享库与内核模块, 由 ld.so / insmod 加载, 不经 execve
      2. 固件分区数据 —— *.mdt / *.b00, 是 Android 分区镜像的段, 交给
         fastbootd/liblp 写 flash, 不是可执行程序。它们恰好以 0x7fELF 开头
         是因为 ELF 魔数被复用为分区标识, 不代表语义上是可执行文件。
    """
    real, exempt = [], 0
    for e in entries:
        if e["typechar"] != "f":
            continue
        d = e["data"]
        if e["filesize"] < 4 or d[:4] != b"\x7fELF":
            continue
        if e["mode"] & 0o111:
            continue
        n = e["name"]
        if n.endswith(EXEMPT_SUFFIX):
            exempt += 1
            continue
        if n.endswith(FIRMWARE_SUFFIX) and FIRMWARE_PATH_MARK in n:
            exempt += 1
            continue
        real.append((n, e["filesize"], e["mode"]))
    return real, exempt


def main():
    if len(sys.argv) < 2:
        print("用法: assert_perm_in_img.py <boot.img> [更多 .img ...]")
        print("  对已封装的产物做执行位断言, 校验对象 = 最终交付物")
        return 2

    print(">>> 产物级执行位断言 (校验对象 = .img 本身, 非中间目录)")
    failed = False
    checked = 0

    for img in sys.argv[1:]:
        if not os.path.isfile(img):
            print("!! %s: 文件不存在" % img)
            failed = True
            continue
        #ramdisk-recovery.img 这类裸 ramdisk 没有 boot header, 直接当 LZ4 解
        try:
            with open(img, "rb") as fh:
                head = fh.read(8)
            if head[:8] == BOOT_MAGIC:
                blob, ksz = read_boot_ramdisk(img)
                kind = "boot.img(kernelless=%s)" % (ksz == 0)
            else:
                with open(img, "rb") as fh:
                    blob = fh.read()
                ksz = -1
                kind = "裸 ramdisk"
            raw, blocks = decompress_android_lz4(blob)
            ents, consumed = parse_cpio_newc(raw)
        except Fail as ex:
            print("!! %s: %s" % (os.path.basename(img), ex))
            failed = True
            continue

        real, exempt = classify_missing_exec(ents)
        nblk = len([b for b in blocks if b[0] != "END"])
        print(">>> %s  [%s]" % (os.path.basename(img), kind))
        print("    ramdisk %d B -> %d B  LZ4块=%d  cpio条目=%d (消费 %d/%d)"
              % (len(blob), len(raw), nblk, len(ents), consumed, len(raw)))
        print("    缺执行位的 ELF: 真缺陷 %d, 设计豁免 %d (.so/.ko/固件分区数据)"
              % (len(real), exempt))
        checked += 1
        if real:
            failed = True
            for name, fsz, mode in sorted(real, key=lambda t: -t[1]):
                print("    !! %-56s size=%-9d mode=%o" % (name, fsz, mode))
            print("    >> 判定: 产物内存在无执行位的可执行程序,修复未真正生效")
        else:
            print("    >> 判定: PASS, 产物内可执行程序执行位齐备")

    if not checked:
        print("")
        print("!! 未成功解析任何镜像(全部失败), 拒绝输出 PASS")
        return 1

    if failed:
        print("")
        print("!! 产物级执行位断言失败 —— chmod 落在镜像封装之后, 未进产物")
        print("!! 修法: chmod 必须在 mka 之前, 或改为产物级后处理(解 ramdisk 改 mode 再重封装)")
        return 1

    print("")
    print(">>> 产物级执行位断言 PASS: %d 个产物的可执行程序执行位齐备" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
