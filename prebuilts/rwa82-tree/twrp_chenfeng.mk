#
# Copyright (C) 2025 The TWRP Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

DEVICE_PATH := device/xiaomi/sm8650

# Inherit from device.mk configuration
$(call inherit-product, $(DEVICE_PATH)/device.mk)

# dependencies
PRODUCT_COPY_FILES += $(call find-copy-subdir-files,*,device/xiaomi/sm8650/prebuilts/chenfeng,recovery/root/vendor)

# Release name
PRODUCT_RELEASE_NAME := chenfeng

## Device identifier
PRODUCT_DEVICE := sm8650
PRODUCT_NAME := twrp_chenfeng
PRODUCT_BRAND := Xiaomi
PRODUCT_MODEL := sm8650
PRODUCT_MANUFACTURER := Xiaomi

