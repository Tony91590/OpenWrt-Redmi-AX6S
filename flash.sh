#!/bin/sh
. /lib/functions.sh
klogger() {
    local msg1="$1"
    local msg2="$2"
    if [ "$msg1" = "-n" ]; then
        echo -n "$msg2" >> /dev/kmsg 2>/dev/null
        echo -n "$msg2"
    else
        echo "$msg1" >> /dev/kmsg 2>/dev/null
        echo "$msg1"
    fi
    return 0
}
hndmsg() {
    if [ -n "$msg" ]; then
        echo "$msg"
        echo "$msg" >> /dev/kmsg 2>/dev/null
        echo $log > /proc/sys/kernel/printk
        stty intr ^C
        exit 1
    fi
}
uperr() {
    exit 1
}
pipe_upgrade_rootfs_ubi() {
    local mtd_dev=mtd$1
    local package=$2
    if [ -f $package -a $1 ]; then
        klogger -n "Burning rootfs image to $mtd_dev ..."
        ubiformat /dev/$mtd_dev -f $package -s 2048 -O 2048 -y
        if [ $? -eq 0 ]; then
            klogger "Done"
        else
            klogger "Error"
            uperr
        fi
    fi
}
verify_rootfs_ubifs() {
    local mtd_devn=$1
    local temp_ubi_data_devn=9
    klogger "Check if mtd$mtd_devn can be attached as an ubi device ..."
    # Try attach the device
    ubiattach /dev/ubi_ctrl -d $temp_ubi_data_devn -m $mtd_devn -O 2048
    if [ "$?" == "0" ]; then
        klogger "PASSED"
        ubidetach -d $temp_ubi_data_devn
        return 0
    else
        klogger "FAILED"
        return 1
    fi
}
board_prepare_upgrade() {
    # gently stop pppd, let it close pppoe session
    ifdown wan
    timeout=5
    while [ $timeout -gt 0 ]; do
        pidof pppd >/dev/null || break
        sleep 1
        let timeout=timeout-1
    done
    # down backhauls
    #ifconfig eth3 down
    #ifconfig wl01 down
    #ifconfig wl11 down
    # clean up upgrading environment
    # call shutdown scripts with some exceptions
    wait_stat=0
    klogger "@Shutdown service "
    for i in /etc/rc.d/K*; do
        # filter out K01reboot-wdt and K99umount
        case $i in
            *reboot-wdt | *umount)
                klogger "$i skipped"
                continue
            ;;
        esac
        [ -x "$i" ] || continue
        # wait for high-priority K* scripts to finish
        if echo "$i" | grep -qE "K7"; then
            if [ $wait_stat -eq 0 ]; then
                wait
                sleep 2
                wait_stat=1
            fi
            klogger "  service $i shutdown 2>&1"
            $i shutdown 2>&1
        else
            klogger "  service $i shutdown 2>&1 &"
            $i shutdown 2>&1 &
        fi
    done
    # try to kill all userspace processes
    # at this point the process tree should look like
    # init(1)---sh(***)---flash.sh(***)
    klogger "@Killing user process "
    for i in $(ps w | grep -v "flash.sh" | grep -v "/bin/ash" | grep -v "PID" | grep -v watchdog | awk '{print $1}'); do
        if [ $i -gt 100 ]; then
            # skip if kthread
            [ -f "/proc/${i}/cmdline" ] || continue
            [ -z "`cat /proc/${i}/cmdline`" ] && {
                klogger " $i is kthread, skip"
                continue
            }
            klogger " kill user process {`ps -w | grep $i | grep -v grep`} "
            kill $i 2>/dev/null
            # TODO: Revert to SIGKILL after watchdog bug is fixed
            # kill -9 $i 2>/dev/null
        fi
    done
    # flush cache and dump meminfo
    sync
    echo 3>/proc/sys/vm/drop_caches
    klogger "@dump meminfo"
    klogger "`cat /proc/meminfo | xargs`"
}
board_start_upgrade_led() {
    gpio 1 1
    gpio 3 1
    gpio l 1000 2
}
board_system_upgrade() {
    local filename=$1
    uboot_mtd=$(grep '"0:APPSBL"' /proc/mtd | awk -F: '{print substr($1,4)}')
    crash_mtd=$(grep '"crash"' /proc/mtd | awk -F: '{print substr($1,4)}')
    #kernel0_mtd=$(grep '"kernel0"' /proc/mtd | awk -F: '{print substr($1,4)}')
    #kernel1_mtd=$(grep '"kernel1"' /proc/mtd | awk -F: '{print substr($1,4)}')
    rootfs0_mtd=$(grep '"rootfs"' /proc/mtd | awk -F: '{print substr($1,4)}')
    rootfs1_mtd=$(grep '"rootfs_1"' /proc/mtd | awk -F: '{print substr($1,4)}')
    os_idx=$(nvram get flag_boot_rootfs)
    rootfs_mtd_current=$(($rootfs0_mtd+${os_idx:-0}))
    rootfs_mtd_target=$(($rootfs0_mtd+$rootfs1_mtd-$rootfs_mtd_current))
    #kernel_mtd_current=$(($rootfs_mtd_current-2))
    #kernel_mtd_target=$(($kernel0_mtd+$kernel1_mtd-$kernel_mtd_current))
    #pipe_upgrade_uboot $uboot_mtd $filename
    #pipe_upgrade_kernel $kernel_mtd_target $filename
    pipe_upgrade_rootfs_ubi $rootfs_mtd_target $filename
    # back up etc
    rm -rf /data/etc_bak
    cp -prf /etc /data/etc_bak
}
upgrade_param_check() {
    if [ -z "$1" -o ! -f "$1" ]; then
        klogger "USAGE: $0 input.bin [1:restore defaults, 0:don't] [1:don't reboot, 0:reboot]"
        exit 1
    fi
    flg_ota=`nvram get flag_ota_reboot`
    if [ "$flg_ota" = "1" ]; then
        klogger "flag_ota_reboot is set ?"
        exit 1
    fi
    cur_ver=`cat /usr/share/xiaoqiang/xiaoqiang_version`
    klogger "Begin Ugrading..., current version: $cur_ver"
    sync
    model=`cat /proc/xiaoqiang/model`
    [ "$model" != "R4A" -a "$model" != "R3GV2" ] && echo 3 > /proc/sys/vm/drop_caches
}
upgrade_prepare_dir() {
    absolute_path=`echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"`
    mount -o remount,size=100% /tmp
    rm -rf /tmp/system_upgrade
    mkdir -p /tmp/system_upgrade
    if [ ${absolute_path:0:4} = "/tmp" ]; then
        file_in_tmp=1
        mv $absolute_path /tmp/system_upgrade/
    else
        file_in_tmp=0
        cp $absolute_path /tmp/system_upgrade/
    fi
}
upgrade_done_set_flags() {
    # tell server upgrade is finished
    [ -f /etc/config/messaging -a -f /sbin/uci ] && {
        /sbin/uci set /etc/config/messaging.deviceInfo.UPGRADE_STATUS_UPLOAD=0
        /sbin/uci commit
        klogger "messaging.deviceInfo.UPGRADE_STATUS_UPLOAD=`uci get /etc/config/messaging.deviceInfo.UPGRADE_STATUS_UPLOAD`"
        klogger "/etc/config/messaging : `cat /etc/config/messaging`"
    }
    # update nvram setting when upgrading
    if [ "$2" = "1" ]; then
        nvram set restore_defaults=1
        klogger "Restore defaults is set."
    else
        nvram set restore_defaults=2
    fi
    [ "$upkernel" = "true" ] && nvram set flag_ota_reboot=1
    nvram set flag_upgrade_push=1
    nvram commit
    if [ "$3" = "1" ]; then
        klogger "Skip rebooting..."
    else
        klogger "Rebooting..."
        reboot
    fi
}
uploadUpgrade() {
    [ "1" = "`cat /proc/xiaoqiang/ft_mode`" ] && return 0
    [ "YES" != "`uci -q get xiaoqiang.common.INITTED`" ] && return 0
    wanstatus=`ubus call network.interface.wan status | grep up | grep false`
    if [ "$wanstatus" = "" ];then
        logger stat_points_none upgrade=start
        [ -f /usr/sbin/StatPoints ] && /usr/sbin/StatPoints
    fi
}
#check pid exist
pid_file="/tmp/pid_xxxx"
if [ -f $pid_file ]; then
    exist_pid=`cat $pid_file`
    if [ -n $exist_pid ]; then
        kill -0 $exist_pid 2>/dev/null
        if [ $? -eq 0 ]; then
            klogger "Upgrading, exit... $?"
            exit 1
        else
            echo $$ > $pid_file
        fi
    else
        echo $$ > $pid_file
    fi
else
    echo $$ > $pid_file
fi
upgrade_param_check $1
# image verification...
uploadUpgrade
board_start_upgrade_led
# stop services
# board_prepare_upgrade
# prepare to extract file
filename=`basename $1`
upgrade_prepare_dir $1
cd /tmp/system_upgrade
# start board-specific upgrading...
klogger "Begin Upgrading and Rebooting..."
board_system_upgrade $filename $2 $3
# some board may reset after system upgrade and not reach here
# clean up
cd /
cap=700
curcap=`du -sk /tmp/system_upgrade/|awk '{print $1}'`
if [[ $curcap -gt $cap ]] ; then
    upkernel=true
fi
rm -rf /tmp/system_upgrade
upgrade_done_set_flags $1 $2 $3
