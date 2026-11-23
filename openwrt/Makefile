# SPDX-License-Identifier: MIT
#
# deskgw 的 OpenWrt 包定义。
# Go 二进制由 CI 静态交叉编译后随 release 分发，本 Makefile 只负责取回二进制，
# 与 UCI 配置、procd 服务、LuCI 视图一起装进 ipk / apk。

include $(TOPDIR)/rules.mk

PKG_NAME:=deskgw
PKG_VERSION:=0.3.9
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=mylucien

DESKGW_BIN_TAG?=bin
DESKGW_BIN_BASE?=https://github.com/mylucien/deskgw/releases/download/$(DESKGW_BIN_TAG)

include $(INCLUDE_DIR)/package.mk

define Package/deskgw
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=deskgw Web 远程桌面网关
  DEPENDS:=+luci-base
  URL:=https://github.com/mylucien/deskgw
endef

define Package/deskgw/description
 在路由器上提供基于浏览器的 Windows 远程桌面网关。包含 HTTPS 管理界面、
 多用户与主机授权、审计日志、RDP 隧道与浏览器端 NLA 认证、应用内多标签
 会话，以及基于 SMB 的文件传输。
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	@case "$(ARCH_PACKAGES)" in x86_64|aarch64_cortex-a53) ;; *) \
		echo "deskgw: 架构 $(ARCH_PACKAGES) 没有预编译二进制"; exit 1 ;; esac
	if [ -f ./prebuilt/$(ARCH_PACKAGES)/deskgw-$(ARCH_PACKAGES).tar.gz ]; then \
		cp ./prebuilt/$(ARCH_PACKAGES)/deskgw-$(ARCH_PACKAGES).tar.gz $(PKG_BUILD_DIR)/ ; \
	else \
		$(CURL) -fsSL "$(DESKGW_BIN_BASE)/deskgw-$(ARCH_PACKAGES).tar.gz" \
			-o $(PKG_BUILD_DIR)/deskgw-$(ARCH_PACKAGES).tar.gz ; \
	fi
	$(TAR) -xzf $(PKG_BUILD_DIR)/deskgw-$(ARCH_PACKAGES).tar.gz -C $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/deskgw/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/deskgw $(1)/usr/bin/deskgw

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/deskgw $(1)/etc/config/deskgw

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/deskgw $(1)/etc/init.d/deskgw

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/95-deskgw $(1)/etc/uci-defaults/95-deskgw

	$(INSTALL_DIR) $(1)/usr/libexec/deskgw
	$(INSTALL_BIN) ./files/usr/libexec/deskgw/cert-fingerprint.sh $(1)/usr/libexec/deskgw/

	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/deskgw $(1)/lib/upgrade/keep.d/deskgw

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/usr/share/luci/menu.d/luci-app-deskgw.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-deskgw.json $(1)/usr/share/rpcd/acl.d/

	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/deskgw
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/deskgw/overview.js \
		$(1)/www/luci-static/resources/view/deskgw/overview.js
endef

define Package/deskgw/postinst
#!/bin/sh
# uci-defaults 默认只在首次启动时由 /etc/init.d/boot 执行；
# 安装完立即运行一次，保证「装完即自启」与 README 一致。
[ -n "$${IPKG_INSTROOT}" ] || {
	# apk 集成会在安装阶段先执行并删除 uci-defaults（脚本末尾自删），
	# 这里只在文件仍存在时补跑，避免每次安装都打印 not found。
	[ -x /etc/uci-defaults/95-deskgw ] && /etc/uci-defaults/95-deskgw || true
	/etc/init.d/deskgw enable
	/etc/init.d/deskgw restart
}
exit 0
endef

$(eval $(call BuildPackage,deskgw))
