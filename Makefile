include $(TOPDIR)/rules.mk

PKG_NAME:=yantd
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/yantd/default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=yantd - yet another network traffic daemon
endef

define Package/yantd
  $(Package/yantd/default)
  MENU:=1
endef

define Package/yantd/description
  yantd is a ...
endef

define Build/Prepare
  mkdir -p $(PKG_BUILD_DIR)
  $(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/yantd/conffiles
/etc/config/yantd
endef

define Package/yantd/install
  $(INSTALL_DIR) $(1)/etc/init.d
  $(INSTALL_BIN) ./files/yantd.init $(1)/etc/init.d/yantd
  $(INSTALL_DIR) $(1)/etc/config
  $(INSTALL_CONF) ./files/yantd.config $(1)/etc/config/yantd
  $(INSTALL_DIR) $(1)/usr/sbin
  $(INSTALL_BIN) $(PKG_BUILD_DIR)/yantd $(1)/usr/sbin/yantd
  $(INSTALL_DIR) $(1)/usr/bin
  $(INSTALL_BIN) $(PKG_BUILD_DIR)/yantd-cli $(1)/usr/bin/yantd-cli
endef

$(eval $(call BuildPackage,yantd))
