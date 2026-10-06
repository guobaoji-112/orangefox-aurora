#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELF 解析（用于 Android ramdisk 内依赖闭包验证）。

实现要点:
- 正确处理 32/64 位 ELF program header
- 通过 section header 精确定位 .dynstr / .dynsym（避免按 PT_DYNAMIC 猜偏移导致越界）
- 正确枚举动态符号，处理 ARM64 的 STT_GNU_IFUNC
"""
import struct


class ElfError(Exception):
    pass


class Elf:
    EM_AARCH64 = 183
    EM_ARM = 40
    EM_X86_64 = 62

    def __init__(self, data):
        self.data = data
        self.is64 = False
        self.machine = None
        self.soname = None
        self.needed = []
        self.rpath = []
        self.runpath = []
        self.dynsym_defs = set()      # 导出的 GLOBAL/WEAK 定义符号
        self.dynsym_unds = set()      # 未定义符号
        self.parse()

    # ---------------------------------------------------------- helpers
    def _u16(self, o):
        return struct.unpack_from("<H", self.data, o)[0]

    def _u32(self, o):
        return struct.unpack_from("<I", self.data, o)[0]

    def _u64(self, o):
        return struct.unpack_from("<Q", self.data, o)[0]

    def _str(self, base, off):
        s = base + off
        e = s
        n = len(self.data)
        while e < n and self.data[e] != 0:
            e += 1
        return self.data[s:e].decode("utf-8", "replace")

    # ---------------------------------------------------------- parse
    def parse(self):
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise ElfError("not ELF")
        ei_class = d[4]
        self.is64 = ei_class == 2
        self.machine = self._u16(18)

        if self.is64:
            e_shoff = self._u64(40)
            e_shentsize = self._u16(58)
            e_shnum = self._u16(60)
            e_shstrndx = self._u16(62)
        else:
            e_shoff = self._u32(32)
            e_shentsize = self._u16(46)
            e_shnum = self._u16(48)
            e_shstrndx = self._u16(50)

        # 收集 section headers
        shs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            if o + e_shentsize > len(d):
                break
            if self.is64:
                sh = {
                    "name": self._u32(o), "type": self._u32(o + 4),
                    "flags": self._u64(o + 8), "addr": self._u64(o + 16),
                    "off": self._u64(o + 24), "size": self._u64(o + 32),
                    "link": self._u32(o + 40), "info": self._u32(o + 44),
                    "align": self._u64(o + 48), "entsize": self._u64(o + 56),
                }
            else:
                sh = {
                    "name": self._u32(o), "type": self._u32(o + 4),
                    "flags": self._u32(o + 8), "addr": self._u32(o + 12),
                    "off": self._u32(o + 16), "size": self._u32(o + 20),
                    "link": self._u32(o + 24), "info": self._u32(o + 28),
                    "align": self._u32(o + 32), "entsize": self._u32(o + 36),
                }
            shs.append(sh)
        if not shs:
            raise ElfError("no section headers")

        # section 名字符串表（用于识别 .dynstr/.dynsym）
        shstr = b""
        if e_shstrndx < len(shs):
            shstr = d[shs[e_shstrndx]["off"]:shs[e_shstrndx]["off"] + shs[e_shstrndx]["size"]]

        def secname(sh):
            s = sh["name"]
            e = s
            while e < len(shstr) and shstr[e] != 0:
                e += 1
            return shstr[s:e].decode("utf-8", "replace")

        dynstr_off = dynstr_size = None
        dynsym_sec = None
        for sh in shs:
            nm = secname(sh)
            if nm == ".dynstr":
                dynstr_off = sh["off"]
                dynstr_size = sh["size"]
            elif nm == ".dynsym":
                dynsym_sec = sh
            elif nm == ".dynamic" and dynsym_sec is None:
                pass

        # DT_NEEDED / SONAME / RUNPATH 来自 .dynamic
        dyn_sec = None
        for sh in shs:
            if secname(sh) == ".dynamic":
                dyn_sec = sh
                break
        if dyn_sec and dynstr_off is not None:
            ds = d[dyn_sec["off"]:dyn_sec["off"] + dyn_sec["size"]]
            ent = 16 if self.is64 else 8
            for p in range(0, len(ds) - ent + 1, ent):
                if self.is64:
                    tag = struct.unpack_from("<q", ds, p)[0]
                    val = struct.unpack_from("<Q", ds, p + 8)[0]
                else:
                    tag = struct.unpack_from("<i", ds, p)[0]
                    val = struct.unpack_from("<I", ds, p + 4)[0]
                if tag == 0:
                    break
                if tag == 1:      # NEEDED
                    self.needed.append(self._str(dynstr_off, val))
                elif tag == 14:   # SONAME
                    self.soname = self._str(dynstr_off, val)
                elif tag == 15:   # RPATH
                    self.rpath.append(self._str(dynstr_off, val))
                elif tag == 29:   # RUNPATH
                    self.runpath.append(self._str(dynstr_off, val))

        # 动态符号
        if dynsym_sec and dynstr_off is not None:
            symtab = d[dynsym_sec["off"]:dynsym_sec["off"] + dynsym_sec["size"]]
            step = 24 if self.is64 else 16
            n = len(symtab) // step
            for k in range(n):
                o = k * step
                if self.is64:
                    st_name = struct.unpack_from("<I", symtab, o)[0]
                    st_info = symtab[o + 4]
                    st_other = symtab[o + 5]
                    st_shndx = struct.unpack_from("<H", symtab, o + 6)[0]
                else:
                    st_name = struct.unpack_from("<I", symtab, o)[0]
                    st_value = struct.unpack_from("<I", symtab, o + 4)[0]
                    st_info = symtab[o + 12]
                    st_other = symtab[o + 13]
                    st_shndx = struct.unpack_from("<H", symtab, o + 14)[0]
                bind = st_info >> 4
                typ = st_info & 0xF
                if st_name == 0:
                    continue
                nm = self._str(dynstr_off, st_name)
                if not nm:
                    continue
                if st_shndx == 0:   # SHN_UNDEF
                    self.dynsym_unds.add(nm)
                elif bind in (1, 2):  # GLOBAL / WEAK
                    self.dynsym_defs.add(nm)

        # soname 兜底
        if self.soname is None:
            self.soname = None
        self.machine_name = {183: "AArch64", 40: "ARM", 62: "x86_64"}.get(self.machine, str(self.machine))
        self.elf_class = "64-bit" if self.is64 else "32-bit"

    def __repr__(self):
        return "<Elf %s %s soname=%s needed=%d>" % (
            self.elf_class, self.machine_name, self.soname, len(self.needed))