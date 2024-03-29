#!/bin/bash
#
# Copyright (c) 2019-2023 P3TERX <https://p3terx.com>
#
# This is free software, licensed under the MIT License.
# See /LICENSE for more information.
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part2.sh
# Description: OpenWrt DIY script part 2 (After Update feeds)
#

# Custom for REDMI AX6S
sed -i 's/192.168.1.1/192.168.31.1/g' package/base-files/files/bin/config_generate
git clone -b master https://github.com/jerrykuku/luci-theme-argon.git package/luci-theme-argon
git clone -b master https://github.com/jerrykuku/luci-app-argon-config.git package/luci-app-argon-config
