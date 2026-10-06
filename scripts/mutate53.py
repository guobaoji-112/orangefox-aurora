#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run#53 新判据的变异测试 —— 证伪"永真PASS"。

每项都往真实产物里注入一个畸形, 然后跑脚本看是否如期fail-fast。
判据从"4 个 TARGETS 全含"改成"部分命中即要求全含"之后, 必须证明:
  (a) recovery ramdisk 缺件仍被拦住  —— 判据没被放宽
  (b) vendor_boot ramdisk 的真缺陷仍被拦住 —— 分流没有变成免检
  (c) 结构性损坏仍被拦住
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fix_perm_in_img.py")

# 真实产物目录, 按优先级探测:
#   1. 环境变量 OFOX_ARTIFACT_DIR —— CI 上显式指定
#   2. 仓库同级工作区 ofox_artifact/ —— 本地基线产物
#   3. ../../output/ —— CI 上收集产物后的默认位置
#   4. $GITHUB_WORKSPACE/output/
# 找不到就明确报错退出, 绝不静默跳过(静默跳过 = 变异测试形同虚设,
# 判据一旦被放宽成永真 PASS 也不会有人知道)。
def _find_src():
    cands = []
    env = os.environ.get("OFOX_ARTIFACT_DIR")
    if env:
        cands.append(env)
    cands.append(os.path.abspath(os.path.join(HERE, "..", "..", "ofox_artifact")))
    cands.append(os.path.abspath(os.path.join(HERE, "..", "..", "..", "output")))
    gh = os.environ.get("GITHUB_WORKSPACE")
    if gh:
        cands.append(os.path.join(gh, "output"))
    for c in cands:
        if os.path.isfile(os.path.join(c, "ramdisk-recovery.img")):
            return c
    raise SystemExit(
        "!!找不到真实产物目录(需含 ramdisk-recovery.img)。已探测:\n"
        "     %s\n"
        "   用 OFOX_ARTIFACT_DIR 指定, 或先跑通产物收集步骤。"
        % "\n     ".join(cands))


SRC = _find_src()

PY = sys.executable

# 直接复用被测脚本自己的 LZ4/cpio 代码来做变异, 避免另写一份实现
# —— 变异器与被测物共用代码, 若共用代码本身有bug, 变异会失效(假阴性)。
# 所以这里只用它的编解码, 条目定位自己按 cpio newc 规范重新实现。
sys.path.insert(0, HERE)
import fix_perm_in_img as F  # noqa: E402


def _rewrite_cpio(path, edit):
    """解出 ramdisk 明文 -> 对 cpio 字节做 edit(bytes)->bytes -> 原样重封装。"""
    kind, head, _ksz, rsz = F.read_header(path)
    with open(path, "rb") as f:
        if kind == "boot":
            f.seek(0x1000)
        blob = f.read(rsz)
    raw, nblocks, _s = F.lz4_decompress(blob)
    new_raw = edit(raw)
    assert new_raw != raw, "变异未生效(edit 返回了原字节)"
    assert len(new_raw) == len(raw), "变异改变了长度, 会引入无关变量"
    new_blob, _nb, _t = F.lz4_compress_like(new_raw, nblocks)
    out = bytearray()
    if kind == "boot":
        nh = bytearray(head)
        nh[12:16] = int(len(new_blob)).to_bytes(4, "little")
        out += nh
    out += new_blob
    if kind == "boot":
        with open(path, "rb") as f:
            f.seek(0x1000 + rsz)
            out += f.read()
    with open(path, "wb") as f:
        f.write(bytes(out))


def find_entry(raw, want):
    """按 cpio newc 规范定位条目头偏移(不依赖被测脚本的 iter)。"""
    pos, n = 0, len(raw)
    while pos + 110 <= n:
        if raw[pos:pos + 6] not in (b"070701", b"070702"):
            return None
        try:
            fsz = int(raw[pos + 54:pos + 62], 16)
            ns = int(raw[pos + 94:pos + 102], 16)
        except ValueError:
            return None
        if ns <= 0 or ns > 4096 or fsz < 0:
            return None
        name = raw[pos + 110:pos + 110 + ns - 1].decode("utf-8", "replace")
        if name == want:
            return pos
        pos = pos + ((110 + ns + 3) & ~3) + ((fsz + 3) & ~3)
        if name == "TRAILER!!!":
            return None
    return None


def run(path):
    p = subprocess.run([PY, FIX, "--dry-run", path],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def _sha(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def case(name, src, mutate, expect_fail, note):
    # 临时文件必须建在系统临时目录, 不能建在 SRC(真实产物目录)里。
    # 早期版本建在 SRC 下, 一旦中途抛异常(比如断言写错), 就会在ofox_artifact/
    # 里留下截断/变异的 .img 残留; 那些文件会被后续 find ... -name '*.img'
    # 式的收集逻辑扫进来, 表现为"断言器报出一个我没见过的文件" ——
    # 排错方向被带偏。基准目录必须保持只读。
    tmp = tempfile.NamedTemporaryFile(suffix=".img", delete=False)
    tmp.close()
    shutil.copyfile(os.path.join(SRC, src), tmp.name)
    try:
        before = os.path.getsize(tmp.name)
        before_sha = _sha(tmp.name)
        mutate(tmp.name)
        after = os.path.getsize(tmp.name)
        # 变异必须真的改动了文件内容, 否则下面的 rc 没有意义 ——
        # 变异器自身静默失效时, "测试通过"和"判据失效"会长得一模一样。
        # 判据用"大小或 sha256 任一变化", 不能只看大小: 改 magic 的变异
        # 不改文件长度, 只看大小会把它误判成"变异器失效"(A3 曾这样翻车)。
        if (before == after and before_sha == _sha(tmp.name)
                and mutate is not mutate_baseline_vendor):
            print("[FAIL] %s" % name)
            print("       变异未改变文件内容(%d B, sha 未变), 变异器自身失效" % before)
            print("       这一项的结果无效, 不可据此判断判据")
            return False
        rc, out = run(tmp.name)
        ok = (rc != 0) == expect_fail
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        print("       预期 %s -> rc=%d (文件 %d -> %d B)"
              % ("exit 1" if expect_fail else "exit 0", rc, before, after))
        print("       %s" % note)
        first = [l for l in out.splitlines() if l.startswith("!!")]
        if first:
            print("       报错: %s" % first[0][:110])
        if not ok:
            print("       !!! 判据失效 —— 详见上面 rc")
        return ok
    finally:
        os.unlink(tmp.name)


def mutate_rename_target(path):
    """把 sbin/bash 改名 -> TARGETS 部分命中, 缺 1 个。"""
    def edit(raw):
        i = find_entry(raw, "sbin/bash")
        assert i is not None, "未找到 sbin/bash 条目"
        j = i + 110
        assert raw[j:j + 9] == b"sbin/bash", "名字偏移不符: %r" % raw[j:j + 9]
        out = bytearray(raw)
        out[j:j + 9] = b"sbin/bxsh"
        return bytes(out)

    _rewrite_cpio(path, edit)


def mutate_vendor_missing_exec(path):
    """给 vendor_boot ramdisk 里的 system/bin/e2fsck 去掉执行位。

    该文件原本是 100755。若新判据把"不含 TARGETS"当成免检, 这个真缺陷
    就会被放过 —— 所以它必须仍被拦下。
    """
    def edit(raw):
        i = find_entry(raw, "system/bin/e2fsck")
        assert i is not None, "未找到 system/bin/e2fsck 条目"
        old = raw[i + 14:i + 22]
        # cpio newc 的 mode 是 8 位十六进制; 常规文件 + rwxr-xr-x = 0o100755 = 0x81ed。
        # 此前误写成 b"0000755"(那是八进制串, 不是 hex), 断言自身先炸了 ——
        # 变异器必须先自证注入点找对, 否则"测试失败"和"判据失效"分不清。
        assert old == b"000081ed", "mode 预期 000081ed(=0o100755), 实得 %r" % old
        out = bytearray(raw)
        out[i + 14:i + 22] = b"000081a4"  # 0o100644
        return bytes(out)

    _rewrite_cpio(path, edit)


def mutate_corrupt_magic(path):
    with open(path, "r+b") as f:
        d = bytearray(f.read())
        d[0:4] = b"\x00\x00\x00\x00"
        f.seek(0)
        f.write(bytes(d))


def mutate_truncate(path):
    """真正把文件截断到 1/3。

    注意: "r+b" 模式下 write() 不会把文件缩短 —— 必须 truncate(),
    否则尾部残留旧字节, 文件根本没变, 变异静默失效(测出来rc=0 是假象)。
    """
    with open(path, "rb") as f:
        d = f.read()
    with open(path, "wb") as f:
        f.write(d[: len(d) // 3])
    assert os.path.getsize(path) == len(d) // 3, "截断未生效"


def mutate_baseline_vendor(path):
    return None


def main():
    print(">>> 变异测试: 证伪永真 PASS (源产物 = ofox_artifact/)")
    print("")
    results = [
        case("A1 recovery 缺件(改名 sbin/bash -> bxsh)",
             "ramdisk-recovery.img", mutate_rename_target, True,
             "新判据的核心承诺: 部分命中仍要求全含"),
        case("A2 vendor_boot 内真缺执行位(e2fsck 100755 -> 100644)",
             "ramdisk.img", mutate_vendor_missing_exec, True,
             "分流不得退化为免检"),
        case("A3 LZ4 magic 损坏",
             "ramdisk-recovery.img", mutate_corrupt_magic, True,
             "结构损坏仍须拦下"),
        case("A4 文件截断至 1/3",
             "ramdisk-recovery.img", mutate_truncate, True,
             "截断仍须拦下"),
        case("B1 基线: 未改动的 vendor_boot ramdisk",
             "ramdisk.img", mutate_baseline_vendor, False,
             "这正是 run#52 的误报对象, 现在必须放行"),
        case("B2 基线: 未改动的 recovery ramdisk",
             "ramdisk-recovery.img", mutate_baseline_vendor, False,
             "正常 recovery ramdisk 应能走通修复"),
    ]
    print("")
    n_ok = sum(1 for r in results if r)
    print(">>> %d/%d 项符合预期" % (n_ok, len(results)))
    if n_ok != len(results):
        print(">>> 存在判据失效项, 不得据此推送")
        return 1
    print(">>> 新判据既未放宽(变异项全被拦), 也未误伤(基线项放行)")
    return 0


if __name__ == "__main__":
    sys.exit(main())