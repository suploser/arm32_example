adb root
adb push ./ls2 /data/user/ls
adb shell "chmod 777 /data/user/ls"
adb shell "/data/user/ls"