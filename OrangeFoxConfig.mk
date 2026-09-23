# OrangeFoxConfig.mk — Xiaomi 14 Ultra (aurora) 橙狐配置
# 由 build_fox_aurora.sh 自动放置并被 BoardConfig.mk include
# 参考橙狐官方变量表: https://wiki.orangefox.tech/en/dev/variables

# ---- 屏幕(2K 3200x1440) ----
OF_SCREEN_H := 3200
OF_STATUS_H := 100          # 状态栏高度,UI 错位时微调
OF_STATUS_INDENT_LEFT := 64
OF_STATUS_INDENT_RIGHT := 64
OF_CLOCK_POS := 1           # 时钟居中(可改 0 靠左)
OF_ALLOW_OFFSETS := 0

# ---- 橙狐功能 ----
FOX_USE_BASH_SHELL_BINARY := 1
FOX_USE_TAR_BINARY := 1
FOX_USE_SED_BINARY := 1
FOX_USE_XZ_UTILS := 1
FOX_USE_NANO_EDITOR := 1
OF_ENABLE_USB_STORAGE := 1
OF_SUPPORT_ALL_BLOCK_DEVICES := 0   # 动态分区机型,避免误操作裸块设备
OF_FIX_OTA_UPDATE_MANIFEST := 1
OF_DISABLE_MIUI_OTA_SPECIFIC_DEVICES := 0

# ---- 备份策略(VAB 机型:fstab 只暴露 super,不得单独备份动态分区) ----
OF_NO_SPLASH_IMAGE := 0

# ---- 外观 ----
OF_USE_GREEN_LED := 1
OF_CLOCK_WIDGET := 1
OF_FL_PATH1 := /sys/class/leds/led:flash_0/brightness

# ---- 设备信息 ----
# 注意: 值里绝不能再写双引号! orangefox.mk 会用 -DVAR='"$(VAR)"' 再包一层,
# 内嵌引号会展开成 ""unofficial... → C++11 user-defined-literal 硬错 (#20 实锤:
# orscmd.o <command line>:28:25 invalid suffix, 列位 25 与 #define OF_MAINTAINER 精确吻合)
OF_DEVICE_NAME := Xiaomi 14 Ultra
OF_MAINTAINER := unofficial (ported from RWA82 sm8650 TWRP tree)
