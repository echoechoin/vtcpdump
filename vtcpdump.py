#!/usr/bin/python3
import os
import sys
import signal
TAP_NAME_IN_KERNEL_SPACE = "vtcpdump_tap"

def vpp_interface_list()->list:
    vpp_if_list = []
    vpp_if_list = os.popen("vppctl show int | grep '^\w' | awk '{print $1}'").readlines()
    for i in range(len(vpp_if_list)):
        vpp_if_list[i] = vpp_if_list[i].strip()
    return vpp_if_list

def vpp_create_tap_device()->str:
    tap_if_name = os.popen("vppctl create tap host-if-name %s".TAP_NAME_IN_KERNEL_SPACE).read().strip()
    os.system("vppctl set int state %s up" % tap_if_name)
    return tap_if_name

def vpp_set_interface_span(if_name, tap_if_name):
    return os.popen("vppctl set int span %s %s both" % (if_name, tap_if_name)).read()

def vpp_set_promiscuous_mode(if_name: str, mode:str)->None:
    if mode == "on":
        os.system("vppctl set int promisc on %s" % if_name)
    elif mode == "off":
        os.system("vppctl set int promisc off %s" % if_name)

def vpp_get_tap_list()->list:
    tap_list_map = []
    tap_list = os.popen("vppctl show tap | grep '^Interface:' -A 1").read().split("--")
    for i in range(len(tap_list)):
        tap_list[i] = tap_list[i].split()
        tap_list_map.append([tap_list[i][1],tap_list[i][5][1:-1]])
    return tap_list_map

def vpp_clear_last_tap_config(fun)->None:
    def inner():
        tap_list = vpp_get_tap_list()
        for i in range(len(tap_list)):
            if tap_list[i][1] == TAP_NAME_IN_KERNEL_SPACE:
                os.system("vppctl delete tap {}".format(tap_list[i][0]))
                break
        fun()
    return inner

def check_is_root_user(func)->None:
    def inner():
        if os.geteuid() != 0:
            print("Please run as root user")
            sys.exit(1)
        func()
    return inner

def check_tcpdump_is_exist(func)->None:
    def inner():
        if os.system("which tcpdump >>/dev/null") != 0:
            print("tcpdump command not found. (try `sudo apt-get install tcpdump`)")
            sys.exit(1)
        func()
    return inner

def check_vpp_is_exist(func)->None:
    def inner():
        if os.system("vppctl show version >>/dev/null") != 0:
            print("vpp may not running. (checked by `vppctl show version`)")
            sys.exit(1)
        func()
    return inner

def tcpdump_get_cmd(tap_if_name:str)->str:
    tcpdump_cmd = "tcpdump "
    for i in range(len(sys.argv)):
        if i == 0:
            continue
        if sys.argv[i].startswith("-") and sys.argv[i].endswith("i") and i < len(sys.argv) - 1:
            sys.argv[i + 1] = tap_if_name
        tcpdump_cmd += sys.argv[i] + " "
    return tcpdump_cmd

def tcpdump_get_interface_from_cmd(args:list)-> str:
    interface = ""
    for i in range(len(args)):
        if args[i] == "-i":
            interface = args[i+1]
            break
    return interface

@vpp_clear_last_tap_config
@check_tcpdump_is_exist
@check_vpp_is_exist
@check_is_root_user
def main()->None:
    vpp_if_list = vpp_interface_list()
    vpp_if_name = tcpdump_get_interface_from_cmd(sys.argv)
    if vpp_if_name == "":
        print("Please use -i to specify interface:")
        for i in range(len(vpp_if_list)):
            print("{}. {}".format(str(i), vpp_if_list[i]))
        sys.exit(1)

    if vpp_if_name not in vpp_if_list:
        print("Interface {} is not a vpp interface".format(vpp_if_name))
        sys.exit(1)

    def sighander(*args, **kwargs):
        delete_cmd = "vppctl delete tap {} >>/dev/null".format(vpp_tap_if_name)
        os.system(delete_cmd)
        vpp_set_promiscuous_mode(vpp_if_name, "off")

    vpp_tap_if_name = ""
    signal.signal(signal.SIGINT, sighander)
    signal.signal(signal.SIGHUP, sighander)
    signal.signal(signal.SIGTERM, sighander)

    vpp_tap_if_name = vpp_create_tap_device()
    vpp_set_interface_span(vpp_if_name, vpp_tap_if_name)
    vpp_set_promiscuous_mode(vpp_if_name, "on")
    os.system(tcpdump_get_cmd(TAP_NAME_IN_KERNEL_SPACE))
    sighander()
    sys.exit(0)

if __name__ == "__main__":
    main()
