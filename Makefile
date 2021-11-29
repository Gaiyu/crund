# This is free software, licensed under the GNU General Public License v2.                                                         
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=crund
PKG_VERSION:=0.5
PKG_RELEASE:=1

PKG_MAINTAINER:=Gaiyu <gaiyu8@163.com>
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk

define Package/crund
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Embedded container engine
	DEPENDS:= +jshn +socat +getopt +libcap
endef

define Package/crund/description
Embedded container engine
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/crund/install
	$(INSTALL_DIR) $(1)
	$(CP) -rfd ./files/* $(1)/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/crund_launcher $(1)/usr/lib/crund/crund_launcher
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/crund_exec $(1)/usr/lib/crund/crund_exec
endef

$(eval $(call BuildPackage,crund))
