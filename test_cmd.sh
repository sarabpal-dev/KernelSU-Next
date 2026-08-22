#!/bin/sh
mkdir -p /data/adb/modules/test-module
echo "id=test-module" > /data/adb/modules/test-module/module.prop
echo "name=Test Module" >> /data/adb/modules/test-module/module.prop
echo "version=v1.0" >> /data/adb/modules/test-module/module.prop
echo "versionCode=1" >> /data/adb/modules/test-module/module.prop
echo "author=test" >> /data/adb/modules/test-module/module.prop
echo "description=Test" >> /data/adb/modules/test-module/module.prop
echo "#!/system/bin/sh" > /data/adb/modules/test-module/uninstall.sh
echo "exit 0" >> /data/adb/modules/test-module/uninstall.sh
chmod 755 /data/adb/modules/test-module/uninstall.sh
touch /data/adb/modules/test-module/remove
ls -la /data/adb/modules/test-module
