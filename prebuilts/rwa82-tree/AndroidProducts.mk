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

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/twrp_chenfeng.mk \
    $(LOCAL_DIR)/twrp_houji.mk \
    $(LOCAL_DIR)/twrp_shennong.mk \
    $(LOCAL_DIR)/twrp_aurora.mk \
    $(LOCAL_DIR)/twrp_zorn.mk \
    $(LOCAL_DIR)/twrp_peridot.mk \
    $(LOCAL_DIR)/twrp_ruyi.mk

COMMON_LUNCH_CHOICES := \
    twrp_chenfeng-eng \
    twrp_houji-eng \
    twrp_shennong-eng \
    twrp_aurora-eng \
    twrp_zorn-eng \
    twrp_peridot-eng \
    twrp_ruyi-eng

