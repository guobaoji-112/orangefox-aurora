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
5. **文件总长必须与原文件完全一致**(= 分区容量上限 104857600), 且不超过上限。
   见下面"AVB footer 与尾部容量"一节 —— 这是第二版修掉致命缺陷的那条。
6. AVB footer 的 `original_image_size` 必须同步更新为新的镜像长度。

## AVB footer 与尾部容量(第二版修掉的致命缺陷)

第一版把原尾部 padding **原样搬运**, 且用 LZ4 default 模式重压缩。两者叠加:

    原始 ramdisk  47376664 B (压缩率 0.364, LZ4 high_compression)
    重压后 ramdisk 56815549 B (压缩率 0.437, default 模式 —— 比原压缩器差)
    加上原样保留的 57476840 B 尾部 -> 总长 114296485 B

而 recovery 分区容量由设备树硬性给定:

    BOARD_RECOVERYIMAGE_PARTITION_SIZE := 104857600   # 100 MiB

114296485 > 104857600 -> **刷入即因镜像超分区被截断/拒绝**。
第一版的断言器只查mode, 对尺寸毫无察觉, 属于"改对了内容, 却产出了不能刷的镜像"。

实测尾部不是普通 padding, 而是 **AVB footer + 未签名 vbmeta**:

    偏移 0..0x1000        boot header v4
    偏移 0x1000..+rsz    LZ4 legacy ramdisk
    中间                 零填充
    偏移 47382528         vbmeta (832 B, magic AVB0)
    文件末尾 -64          AVB footer (magic AVBf)

vbmeta 解析结果 —— **未签名、无hash 描述符的占位块**:

    algorithm_type        = 0   (NONE)
    hash_size             = 0
    public_key_size       = 0
    descriptors_size      = 0
    auth_data_block_size  = 0

即它不校验镜像任何字节, 但 bootloader 仍按 footer 里的
`original_image_size` 定位 vbmeta。因此**重写 ramdisk 后必须同步改 footer**,
否则 bootloader 会去错误偏移读 vbmeta。

第三版同时把压缩器对齐到上游: LZ4 high_compression level 12。
实测 16 块重压得 47383481 B, 与原始 47376600 B 仅差 +0.014%,
ramdisk 体积回到原量级, 尾部余量充足。
"""

import hashlib
import os
import struct
import sys

BOOT_MAGIC = b"ANDROID!"
AVB0_MAGIC = b"AVB0"
AVB_FOOTER_MAGIC = b"AVBf"
LZ4_MAGIC = 0x184C2102
CPIO_MAGICS = (b"070701", b"070702")
HDR = 110

# recovery 分区容量上限。与设备树 BOARD_RECOVERYIMAGE_PARTITION_SIZE 一致。
# 引用它而不是硬编码: 超限镜像刷不进去, 且症状是启动失败而非刷写报错, 极难定位。
RECOVERY_PARTITION_MAX = 104857600

# 上游 mkbootimg 用的是 LZ4 high_compression。用同一档重压,
# 体积才能回到原量级(实测 level 12 与原产物仅差 +0.014%)。
# 用 default 模式会退到 0.437 压缩率, 直接撑爆 100 MiB 分区。
LZ4_MODE = "high_compression"
LZ4_LEVEL = 12

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


def lz4_compress_like(data, nblocks, max_total=None):
    """重新压缩, 保持 AOSP LZ4 legacy 格式(可被 bootloader 直接解回)。

    ## 为什么块数可以改

    块数是 mkbootimg 内部的流式分块产物, bootloader 只按"读 u32 长度 -> 取块
    -> 逐块解"消费, 不校验块数。所以块数是可自由选择的压缩参数。

    而块数**显著影响**总大小 —— LZ4 每个块独立压缩、无跨块字典, 块越大
    匹配窗口利用率越高。实测同一份 130 MB 明文(HC12):

        16 块(沿用原值)  47383481 B   <- 超出vbmeta 偏移, 放不下
         8 块           47364537 B
         4 块           47357032 B
         2 块           47351165 B
         1 块           47350093 B   <- 比原产物还小 26 KB

    原压缩器留下 1768 B 余量, 而 16 块会超 5069 B。降到 8 块即有充足余量。

    策略: 从原块数开始, 若超 max_total 就逐级减半块数重压, 直到装下。
    这样正常情形保持与原产物同粒度, 只在必要时才降块。
    原"块数必须与原段一致"这条不变式已撤销 —— 它约束的是产物内部布局细节,
    而真正的硬约束是"必须装得进 vbmeta 偏移之前"。
    """
    try:
        import lz4.block
    except ImportError:
        raise Fail("缺少 python-lz4 (pip install lz4)")

    def compress_with(nb):
        chunk = (len(data) + nb - 1) // nb
        res = bytearray()
        res += struct.pack("<I", LZ4_MAGIC)
        i = 0
        got = 0
        while i < len(data):
            ch = bytes(data[i:i + chunk])
            c = lz4.block.compress(ch, store_size=False,
                                   mode=LZ4_MODE, compression=LZ4_LEVEL)
            if len(c) < len(ch):
                res += struct.pack("<I", len(c))
                res += c
            else:
                # 压不小就原样存, 靠 bit31 标记
                res += struct.pack("<I", len(ch) | 0x80000000)
                res += ch
            i += len(ch)
            got += 1
        return bytes(res), got

    nb = nblocks
    blob, got = compress_with(nb)
    if max_total is None:
        return blob, got, nb
    while len(blob) > max_total and nb > 1:
        nb //= 2
        blob, got = compress_with(nb)
    return blob, got, nb


def read_avb_footer(path):
    """读文件末尾的 AVB footer。返回 None 表示这个镜像没有 footer。

    footer 是固定 64 字节, 位于文件末尾, 全部为大端:
        0..4    magic 'AVBf'
        4..8    version_major (BE u32)
        8..12   version_minor (BE u32)
        12..20  original_image_size (BE u64)   <- vbmeta 的偏移, 不是镜像总长
        20..28  (实测全 0)
        28..36  vbmeta_size (BE u64)
        36..64  reserved (实测全 0)

    ## 偏移是怎么最终确定的(此处前后错了三轮, 值得留档)

    肉眼 hexdump 极易读错 —— 页面上 16 字节一行的 hexdump, 若不逐字节编号,
    就会把"行内第几个字节"当成绝对偏移。这个 bug 连续骗了三轮:

        轮 1  按 12/20 读 -> vbmeta_size 读出 47382528(不可能, 远超实际)
        轮 2  改成 16/24 -> original_image_size 读出 2.0e17(荒谬值)
        轮 3  改成 16/28 -> vbmeta_size 对(832)但 original_image_size 仍错

    终局做法: 不再目测, 改为**穷举 + 已知真值反查**。已知 vbmeta 实际在
    偏移 47382528、长度 832, 于是把这两个数的 BE 编码在 footer 里定位:

        47382528 的 8 字节编码出现在偏移 [12, 20]
        832的 8 字节编码出现在偏移 [28]

    偏移 20 处的 47382528 是假阳性(它是 24 处值的低 4 字节被前导 0 拼出的
    另一段重合), 结合"12 才是 footer 字段区起点"才唯一确定 12 与 28。

    **教训: 二进制结构的字段偏移, 必须用已知真值反查 + 结构语义交叉验证,
    绝不能靠 hexdump 目测。**
    """
    with open(path, "rb") as f:
        f.seek(-64, 2)
        ft = f.read(64)
    if len(ft) != 64 or ft[:4] != AVB_FOOTER_MAGIC:
        return None
    return {
        "raw": ft,
        "original_image_size": struct.unpack_from(">Q", ft, 12)[0],
        "vbmeta_size": struct.unpack_from(">Q", ft, 28)[0],
    }


def rebuild_avb_footer(orig_footer, new_vm_offset):
    """按新的 vbmeta 偏移重写 footer。只有 original_image_size 会变。"""
    ft = bytearray(orig_footer["raw"])
    struct.pack_into(">Q", ft, 12, new_vm_offset)
    old = bytes(orig_footer["raw"])
    if bytes(ft[:12]) != old[:12]:
        raise Fail("AVB footer 前 12 字节被改动")
    if bytes(ft[20:]) != old[20:]:
        raise Fail("AVB footer 20 字节之后被改动")
    return bytes(ft)


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

    # ---- 先摸清尾部布局, 才能算出 ramdisk 的体积预算 ----
    # budget = "新 ramdisk 允许占多少字节"(到 vbmeta 偏移为止)。
    # 拿到预算后再压, 避免压完才发现装不下再重来。
    footer = read_avb_footer(path) if kind == "boot" else None
    orig_filesize = os.path.getsize(path)
    if kind == "ramdisk":
        # 裸 ramdisk 是中间产物, 不写任何分区, 没有容量上限。
        # 但仍以"不超原长"为预算 —— 否则重压后可能比原产物更大, 平白浪费
        # 磁盘与上传流量, 且让产物与boot.img 里的那份失去可比性。
        # (不能用 orig_filesize=0 代入会算出 -4096 的负预算, 把自适应
        #  退化到1 块; 这属于语义错误, 只是恰好 1 块压得更小才没炸。)
        budget = orig_filesize
    elif footer is not None:
        budget = footer["original_image_size"] - 0x1000
    else:
        budget = orig_filesize - 0x1000
    new_blob, nblocks_used, blocks_tried = lz4_compress_like(
        new_raw, nblocks, max_total=budget)

    # 自校验1: 重解重压缩结果, 确认改动真的落在字节里
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

        # ---- 尾部: 必须重建, 不能原样搬运 ----
        # 原文件总长 = 分区容量上限, 结构为:
        #     [header][ramdisk][零填充][vbmeta][零填充][AVB footer(末尾 64B)]
        # 旧实现把 ramdisk 之后的全部字节(含 vbmeta 与 footer)原样搬运,
        # 于是 ramdisk 一涨, 总长就跟着涨 -> 超分区。正确做法是保持总长不变。
        with open(path, "rb") as f:
            f.seek(0x1000 + rsz)
            tailbytes = f.read()
        if len(tailbytes) != orig_filesize - 0x1000 - rsz:
            raise Fail("尾部读取长度不符(%d != %d)"
                       % (len(tailbytes), orig_filesize - 0x1000 - rsz))

        # vbmeta 紧接在 original_image_size 处(实测偏移 47382528, 与 footer 字段吻合),
        # 之后是零填充, footer 固定在文件末尾 64 字节。整体布局:
        #     [0, 0x1000)          boot header
        #     [0x1000, +rsz)       ramdisk
        #     [.., vm_off)         零填充
        #     [vm_off, +832)       vbmeta (AVB0)
        #     [.., filesize-64)    零填充
        #     [filesize-64, end)   AVB footer (AVBf)
        #
        # 因此 original_image_size 是 **vbmeta 的偏移**, 不是镜像总长 ——
        # 按"总长"理解会算出 vm_off=0 而被断言当场抓住。
        vbmeta = b""
        if footer is not None:
            vm_off = footer["original_image_size"]
            vm_sz = footer["vbmeta_size"]
            if vm_off < 0x1000 + rsz:
                raise Fail("vbmeta 偏移 %d 落在 ramdisk 内, 布局异常" % vm_off)
            if vm_off + vm_sz > orig_filesize - 64:
                raise Fail("vbmeta 末端 %d 越过 footer 起始 %d, 布局异常"
                           % (vm_off + vm_sz, orig_filesize - 64))
            with open(path, "rb") as f:
                f.seek(vm_off)
                vbmeta = f.read(vm_sz)
            if vbmeta[:4] != AVB0_MAGIC:
                raise Fail("vbmeta magic 非 AVB0: %r" % vbmeta[:4])

        # 重建: header + 新ramdisk + 零填充到 vbmeta 偏移 + vbmeta + 零填充 + footer
        # 总长与footer 全部保持原样 —— 只有中间那段零填充被重新计算。
        body_end = 0x1000 + len(new_blob)
        if footer is None:
            if body_end > orig_filesize:
                raise Fail("新镜像 %d B 已超原长 %d B(无 footer 可裁剪)"
                           % (body_end, orig_filesize))
            tail_new = b"\0" * (orig_filesize - body_end)
            footer_new = b""
            new_total = orig_filesize
        else:
            vm_off = footer["original_image_size"]
            vm_sz = footer["vbmeta_size"]
            if body_end > vm_off:
                raise Fail("新镜像 %d B 已顶到/超出 vbmeta 偏移 %d B, 尾部放不下"
                           % (body_end, vm_off))
            tail_new = (b"\0" * (vm_off - body_end) + vbmeta
                        + b"\0" * (orig_filesize - 64 - vm_off - vm_sz))
            new_total = orig_filesize
            # 总长未变, footer 逐字节复用, 不需要重写
            footer_new = footer["raw"]

        if new_total > RECOVERY_PARTITION_MAX:
            raise Fail("重建后镜像 %d B 超出 recovery 分区容量上限 %d B"
                       % (new_total, RECOVERY_PARTITION_MAX))

        kindlabel = "boot.img(kernelless=%s, AVB footer=%s)" % (
            ksz == 0, "有" if footer else "无")
    else:
        # 裸 ramdisk: 无 header, 无尾部 padding, 不写任何分区
        out_head = b""
        footer_new = b""
        tail_new = b""
        new_total = len(new_blob)
        kindlabel = "裸 ramdisk(中间产物, 不受分区容量约束)"

    report.append(">>> %s  [%s]" % (base, kindlabel))
    report.append("    ramdisk %d B -> %d B  (cpio %d B 恒定, 尾部填充 %d B)"
                  % (rsz, len(new_blob), len(new_raw), tail))
    for name, old, newm in changed:
        report.append("    %-18s %o -> %o" % (name, old, newm))
    report.append("    重压缩 %s/%d: 原%d 块 -> 实用 %d 块(预算 %d B)"
                  % (LZ4_MODE, LZ4_LEVEL, nblocks, nblocks_used, budget))
    if kind == "boot":
        report.append("    文件总长 %d B (容量上限 %d B, 余量 %+d B)"
                      % (new_total, RECOVERY_PARTITION_MAX,
                         RECOVERY_PARTITION_MAX - new_total))
    return True, (kind, out_head, new_blob, tail_new, footer_new,
                  rsz, changed, new_total)


def write_back(path, payload):
    """原子写回, 并从磁盘重新读回复验 —— 不信任内存对象。"""
    (kind, new_head, new_blob, tail_new, footer_new,
     old_rsz, changed, expect_total) = payload
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        if kind == "boot":
            f.write(new_head)
        f.write(new_blob)
        f.write(tail_new)
        if footer_new:
            f.write(footer_new)
    try:
        actual = os.path.getsize(tmp)
        if actual != expect_total:
            raise Fail("写回后文件长度=%d != 预期 %d" % (actual, expect_total))
        if actual > RECOVERY_PARTITION_MAX:
            raise Fail("写回后 %d B 超出分区容量上限 %d B"
                       % (actual, RECOVERY_PARTITION_MAX))
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
        # footer 必须仍在末尾, 且其 original_image_size 仍指向真实 vbmeta 偏移
        if footer_new:
            ft = read_avb_footer(tmp)
            if ft is None:
                raise Fail("写回后 AVB footer 丢失")
            if ft["original_image_size"] + ft["vbmeta_size"] > actual:
                raise Fail("footer 指向的 vbmeta 越界: %d+%d > %d"
                           % (ft["original_image_size"], ft["vbmeta_size"], actual))
            if ft["raw"] != footer_new:
                raise Fail("写回后 footer 字节与预期不一致")
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
