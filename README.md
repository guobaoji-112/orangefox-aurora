# 小米 14 Ultra (aurora) OrangeFox 移植构建包

## 结论先行

- 橙狐官方没有 aurora 适配,但社区有可复用的 TWRP 设备树:
  **https://github.com/RWA82/android_device_xiaomi_sm8650-twrp**
  (统一树,覆盖 aurora / houji / shennong / peridot 等 sm8650 机型,自带 prebuilt kernel)
- 把它接入 OrangeFox 源码树(fork 自 TWRP)重新编译,即可得到橙狐版。
- **编译必须在 Linux 环境**:WSL2(Ubuntu 22.04/24.04)、原生 Linux,或零成本用 GitHub Actions。
  磁盘 ≥ 200GB(fork_14.1 源码约 85GB + 编译产物),内存 ≥ 16GB(建议配 swap)。

## 关于分支选择

- 目标 ROM 是 Android 15(HyperOS 2 / A15 底层)→ 必须用 **fork_14.1** manifest 分支。
- 你手里的 `twrp-3.7.1_16_A15-aurora-Kyuofox.img` 就是 A15 底层的 TWRP,
  说明这棵树(A15 变体)已被验证能点亮、能触控,移植风险集中在橙狐特有的配置项。

## 需要做的移植改动(TWRP 树 → 橙狐)

1. **橙狐配置文件**:仓库里已备好模板 `OrangeFoxConfig.mk`,核心项:
   - `OF_SCREEN_H := 3200`(2K 屏,状态栏/圆角相关偏移按需调)
   - `OF_USE_GREEN_LED / OF_CLOCK_WIDGET` 等外观项按喜好开
   - `FOX_USE_BASH_SHELL_BINARY := 1`、`FOX_USE_NANO_EDITOR := 1`(橙狐招牌功能)
2. **BoardConfig.mk / device.mk 末尾** include 上述配置(脚本会自动打补丁)。
3. **fstab 保持不变**——aurora 是 VAB 动态分区机型,fstab 不得暴露单个动态分区,
   只允许 super 整体备份(橙狐官方维护者规范明确要求)。
4. 构建目标:aurora 无独立 recovery 分区 → 编 **boot image**
   (`mka adbd bootimage`),产出可直接 `fastboot boot` 的 img。

## 法律注意(GPL)

橙狐是 GPL v3+。公开发布你编译的橙狐包时,**必须同时公开你改过的设备树源码**
(放到公开 GitHub/GitLab 仓库),这是硬性义务,不是可选项。

## 刷入方式(提醒)

```bash
fastboot boot OrangeFox-aurora.img   # 临时引导验证
```
确认可用后再在橙狐里"刷入当前 recovery"固化。A15 加密 Data 若无法解密,
需格式化 Data(清空所有数据),先备份。

## 没有编译环境?两条路

### 路线 A(免费,推荐先试):GitHub Actions 云编译

只需 GitHub 账号,不需要自己的电脑有空间:

1. 注册/登录 github.com → 右上角 "+" → **New repository**(名字随意,Public)。
2. 把 `github-actions/build_orangefox.yml` 上传到仓库的 **`.github/workflows/`** 目录,
   把 `OrangeFoxConfig.mk` 上传到仓库根目录(网页上传直接拖文件即可)。
3. 仓库页 → **Actions** → 选 "OrangeFox - 小米14 Ultra (aurora) 云端编译" → **Run workflow**。
4. 跑完后在该次运行页面底部 **Artifacts** 下载 `OrangeFox-aurora`(里面是 boot.img)。

- 源码同步+编译预计 2~5 小时,免费额度(每月 2000 分钟)足够。
- ⚠️ 已知风险:fox_14.1 官方标注 EXPERIMENTAL,且免费 runner 磁盘在深度清理后约 65GB,
  同步阶段有较小概率磁盘不足。若失败,改走路线 B。
- 失败时看 Actions 红叉步骤的日志,把报错发给我即可继续排查。

### 路线 B(最稳,花钱):按小时租云服务器

租一台 16 核 32G / 200G NVMe 的按量付费 VPS(几块钱/小时,用完释放),
Ubuntu 22.04+,然后三条命令:

```bash
apt update && apt install -y git && git clone <你的仓库或把 fox-aurora 目录传上去>
cd fox-aurora && ./build_fox_aurora.sh all     # 依赖+同步+编译一条龙
# 产物: OrangeFox-aurora.img, scp 拉回本地
```

### 刷入

```bash
fastboot boot OrangeFox-aurora.img   # 临时引导验证
```
