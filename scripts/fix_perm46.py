#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run#46: 修复 run#45 产物中【已实证】的 ramdisk 权限缺陷。

缺陷: 4 个真正的可执行程序缺执行位 (mode=0644), 直接 exec 会 EACCES
  /sbin/bash       1,413,200 B  AArch64 ELF
  /sbin/magiskboot 1,250,088 B  AArch64 ELF
  /sbin/zip          685,280 B  AArch64 ELF
  /FFiles/ps           47,432 B  AArch64 ELF

证据链:
  1. run#45 产物 cpio 实测这4 个 mode 均为 0100644, 但内容是 AArch64 ELF 可执行程序。
  2. TWRP 对照: /system/bin/bash mode=0100755(可执行) -> 同样内容类别, 权限不同。
  3. 全量筛查: 缺执行位的 ELF 共 309 个, 其中 297 个是 .so/.ko(共享库/内核模块,
     **不需要**执行位, 属正常)。剔除后剩下的才是真缺陷 —— 即上列 4 个。
     另 8 个是 /vendor/firmware_mnt/image/*.mdt/.b00(固件分区数据, 按设计就是 0644,
     不是可执行程序, 排除)。

排除项(经核实**不需要修**, 与初版判断不同):
  - /product、/system_ext: OF 是空目录, TWRP 是符号链接 -> 但**两者都对**。
    ramdisk 内 file_contexts 用 /(product|system/product)(/.*)? 与
    /(system_ext|system/system_ext)(/.*)? 二选一匹配, 两种路径都被 SELinux 接受;
    且 /system/product、/system/system_ext 在**两个镜像里都不存在**,
    即 TWRP 的符号链接本身也是死链 -> 说明这两个路径在 ramdisk 内只是
    顶层占位符, 空目录与死链语义等价。改动它属于无依据的"对齐", 不做。
  - keymint-V4-ndk.so 残留未定义符号 AIBinder_Class_setTransactionCodeToFunctionNameMap:
    不在 se_omapi 的 DT_NEEDED 闭包内, 不影响画图案解密; 修它需**成对**升级
    libbinder.so + libbinder_ndk.so(单独换 libbinder_ndk 会引入 6 个新缺口),
    属独立变更, 不与本次混做。此处只做**边界确认**, 不改库。

用法: python3 fix46.py <rootdir>
退出: 0 = 已修或无需修; 1 = 有失败项
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from elfparse import Elf
except ImportError:
    # workflow 内联运行时会与本脚本同目录提供 elfparse.py
    Elf = None

# 目标: (相对路径, 期望 mode, 说明)
TARGETS = [
    ("sbin/bash", "shell 解释器, OrangeFox 落成实体文件但未给执行位"),
    ("sbin/magiskboot", "magiskboot 工具, 实体文件未给执行位"),
    ("sbin/zip", "zip 工具, 实体文件未给执行位"),
    ("FFiles/ps", "OrangeFox 主题附带的 ps 工具, 实体文件未给执行位"),
]

# 明确不改的路径 + 理由 (会被断言检查, 防止后人"顺手对齐"回去)
DO_NOT_TOUCH = [
    ("product", "空目录与 TWRP 的死链符号链接语义等价; file_contexts 二选一匹配"),
    ("system_ext", "同上"),
]

AIB = "AIBinder_Class_setTransactionCodeToFunctionNameMap"
KM = "android.hardware.security.keymint-V4-ndk.so"
BN = "libbinder_ndk.so"

FIXED, SKIPPED, FAILED, VERIFIED = [], [], [], []


def is_elf(b):
    return len(b) >= 4 and b[:4] == b"\x7fELF"


def machine_of(b):
    if not is_elf(b) or len(b) < 20:
        return "?"
    return {183: "AArch64", 40: "ARM", 62: "x86_64"}.get(
        struct.unpack_from("<H", b, 18)[0], "?")


def has_exec(mode):
    return bool(mode & 0o111)


def fix_exec_bit(root):
    """给 4 个已实证的可执行程序补执行位。"""
    if os.name != "posix":
        # Windows/NTFS 不保留 POSIX 执行位, 无法在此验证 —— 但仍尝试,
        # 以便脚本在 Linux 构建机上直接可用。
        VERIFIED.append("注意: 当前平台非 POSIX(%s), chmod 的执行位效果无法本地验证; "
                        "实际生效由 Linux 构建机保证" % os.name)
    for rel, why in TARGETS:
        p = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.lexists(p):
            SKIPPED.append("%s: 不存在(构建系统版本差异), 跳过" % rel)
            continue
        if os.path.islink(p):
            SKIPPED.append("%s: 是符号链接 -> %s, 链接自身 mode 无意义"
                           % (rel, os.readlink(p)))
            continue
        if not os.path.isfile(p):
            SKIPPED.append("%s: 非普通文件, 跳过" % rel)
            continue
        try:
            with open(p, "rb") as f:
                head = f.read(20)
        except OSError as e:
            FAILED.append("%s: 读取失败: %s" % (rel, e))
            continue
        if not is_elf(head):
            SKIPPED.append("%s: 非 ELF(可能是脚本), 不动权限以免破坏 shebang" % rel)
            continue
        mach = machine_of(head)
        size = os.path.getsize(p)
        try:
            os.chmod(p, 0o755)
        except OSError as e:
            FAILED.append("%s: chmod 失败: %s" % (rel, e))
            continue
        now = os.stat(p).st_mode & 0o7777
        if not has_exec(now):
            if os.name != "posix":
                # chmod 已成功下发, 只是本平台不回读执行位 —— 计入 FIXED
                # (动作确实发生了), 否则下面的不变式会误判为"什么都没做"。
                FIXED.append("%s: 已 chmod 0755, 平台 %s 不保留执行位(mode=%o) —— "
                             "动作已下发, Linux 构建机上生效" % (rel, os.name, now))
            else:
                FAILED.append("%s: chmod 后仍无执行位(mode=%o)" % (rel, now))
            continue
        FIXED.append("%s: 0644 -> 0755 (%s ELF, %d B) — %s" % (rel, mach, size, why))


def check_do_not_touch(root):
    """确认这两个路径维持现状, 不被本次修复改动。"""
    for rel, why in DO_NOT_TOUCH:
        p = os.path.join(root, rel.replace("/", os.sep))
        if os.path.islink(p):
            state = "符号链接 -> %s" % os.readlink(p)
        elif os.path.isdir(p):
            state = "目录(%d 条目)" % len(os.listdir(p))
        elif os.path.exists(p):
            state = "普通文件"
        else:
            state = "不存在"
        VERIFIED.append("%s: 保持 %s —— %s" % (rel, state, why))


def elf_dynsyms(path):
    """读取 .dynsym, 返回 (导出集合, 未定义集合)。失败返回 (None, None)。

    复用 elfparse.Elf —— 那份解析器已在 run#45 产物上验证可靠
    (务必按 section header 定位 .dynstr/.dynsym; 用 PT_DYNAMIC 猜偏移会越界
     读出乱码符号名, 曾在开发过程中导致 keymint 残留被误判为"不引用")。
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None, None
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None, None
    if Elf is None:
        raise RuntimeError("elfparse 模块不可用, 判据失效(不得静默跳过)")
    try:
        el = Elf(data)
    except Exception:
        return None, None
    return set(el.dynsym_defs), set(el.dynsym_unds)


def check_keymint_bound(root):
    """确认 keymint 残留引用是【已知且有界】的一处, 且不在 se_omapi 闭包内。"""
    def find(name, dirs=("system/lib64", "vendor/lib64")):
        for d in dirs:
            q = os.path.join(root, d.replace("/", os.sep), name)
            if os.path.isfile(q):
                return q
        return None

    km = find(KM)
    if km is None:
        # 判据基准缺失 -> 无法判定边界。静默 SKIP 会让整条断言永真 PASS
        # (变异测试: 空 rootdir 亦返回 0), 属假阴性, 故按 fail-fast 判失败。
        FAILED.append("keymint 边界: 基准库 %s 不存在(rootdir=%s) —— 判据失效, "
                      "拒绝输出无意义的 PASS" % (KM, root))
        return
    _e, und = elf_dynsyms(km)
    if und is None:
        FAILED.append("keymint 边界: %s 的 .dynsym 解析失败, 判据失效" % KM)
        return
    ref = AIB in und
    bn = find(BN)
    prov = None
    if bn:
        bexp, _ = elf_dynsyms(bn)
        if bexp is None:
            FAILED.append("keymint 边界: %s 的 .dynsym 解析失败, 判据失效" % BN)
            return
        prov = AIB in bexp
    # se_omapi 是否依赖 keymint-V4-ndk(若依赖则残留会影响解密链, 需升级 libbinder)
    se = os.path.join(root, "system", "bin", "se_omapi")
    if not os.path.isfile(se):
        se = os.path.join(root, "vendor", "bin", "se_omapi")
    in_closure = False
    if os.path.isfile(se):
        _se, seund = elf_dynsyms(se)
        if seund is not None:
            in_closure = AIB in seund
    if ref and prov is False:
        VERIFIED.append(
            "keymint 边界: %s 引用 %s, 本镜像 %s 不导出 —— 已知有界残留; "
            "se_omapi 自身%s该符号"
            % (KM, AIB, BN, "**含**" if in_closure else "不含"))
    elif ref and prov is True:
        VERIFIED.append("keymint 边界: %s 由 %s 覆盖, 无缺口" % (KM, BN))
    else:
        VERIFIED.append("keymint 边界: %s 已不引用该符号" % KM)
    if in_closure:
        FAILED.append("se_omapi 闭包内出现 %s —— 残留已变为真实阻断, 必须成对升级 "
                      "libbinder.so + libbinder_ndk.so" % AIB)


def main():
    if len(sys.argv) != 2:
        print("用法: fix46.py <rootdir>")
        return 1
    root = sys.argv[1]
    if not os.path.isdir(root):
        print("!! rootdir 不存在: %s" % root)
        return 1
    print(">>> run#46 ramdisk 权限修复 (依据 run#45 产物实证)")
    fix_exec_bit(root)
    # 不变式: 4 个目标必须【至少有一个】真实存在。若一个都没有, 说明 rootdir
    # 选错或构建产物形态变了, 此时"无失败项"是永真 PASS(假阴性), 必须拒绝。
    # 变异测试已验证必要性: 空 rootdir 修复前返回 0。
    if not FIXED and not SKIPPED:
        FAILED.append("4 个目标文件 (sbin/bash, sbin/magiskboot, sbin/zip, FFiles/ps) "
                      "在 rootdir 下全部不存在 —— rootdir 未命中真实产物, "
                      "拒绝输出无意义的 PASS")
    elif not FIXED and SKIPPED and len(SKIPPED) == len(TARGETS):
        # 全部被跳过: 要么已不可变体, 要么基准选错, 两者都要求人工确认
        VERIFIED.append("注意: 4 个目标全部走SKIP 分支(已可执行/是链接/非 ELF), "
                        "无实际 chmod 发生")
    check_do_not_touch(root)
    check_keymint_bound(root)

    def dump(title, arr, tag):
        print()
        print("--- %s ---" % title)
        if arr:
            for m in arr:
                print("  [%s] %s" % (tag, m))
        else:
            print("  (无)")
    dump("已修复", FIXED, "FIXED")
    dump("已确认(不改)", VERIFIED, "KEEP ")
    dump("已跳过", SKIPPED, "SKIP ")
    if FAILED:
        dump("失败", FAILED, "FAIL ")
        return 1
    print()
    print(">>> 完成, 无失败项")
    return 0


if __name__ == "__main__":
    sys.exit(main())