#!/usr/bin/bash
check() {
  return 0
}
depends() {
  return 0
}

installkernel() {
  hostonly='' instmods cdc-acm
}

install() {
  inst_binary "$moddir/host" /usr/bin/host
  inst_binary /usr/sbin/cryptsetup /usr/bin/cryptsetup
  inst_libdir_file "libtss2*.so*"
  inst_libdir_file "libcrypto.so*"
  inst_libdir_file "libz.so*"
  inst_simple "$moddir/tkey-fde.service" /usr/lib/systemd/system/tkey-fde.service
  systemctl --root="$initdir" enable tkey-fde.service
}
