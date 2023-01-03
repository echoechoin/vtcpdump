#!/usr/bin/python3
import re
import os
import sys
import signal
import fcntl
import subprocess

class Vtcpdump(object):
    """
    使用tcpdump抓取vpp网口/网桥的流量: 通过将网口的流量转发到虚拟网口对，然后使用tcpdump抓取虚拟网口对的流量。
    FIXME: 暂时无法通过host参数过滤url (tcpdump.py -ni <interface> host <url>)
    """
    DPDK_PORT_FORMAT   = "^[A-Za-z0-9]*Ethernet[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$"
    PCAP_KERNEL_PORT   = "ray_pcap_out"
    PCAP_VPP_PORT      = "ray_pcap_in"
    LOCK_FILE = "/tmp/vtcpdump.lock"
    def __init__(self):
        self.lock_file_fd          = None # 文件锁
        self.if_list               = []   # vpp可以抓包的网口列表
        self.span_if_list          = []   # 如果是网桥，则需要获取抓包的网口列表
        self.if_name               = None # 需要抓包的网口或者网桥
        # 文件锁，用于保证只有一个vtcpdump进程在运行
        self.flock_check()
        # 检查vpp进程是否存在
        self.vpp_process_check()
        # 获取vpp网口列表
        self.get_vpp_if_list()
        # 获取需要抓包的vpp网口或者网桥
        self.get_tcpdump_if_name(sys.argv[1:])
        # 获取需要抓包的网口列表 (网桥中有多个网口)
        self.get_span_if_list()
        # 注册信号处理函数
        self.sighander_register()
        # 清除之前的环境
        self.clear_ctx()
        # 创建虚拟网口对
        self.create_host_pair()
        # 关联虚拟网口到vpp
        self.vpp_associate_to_host_pair()
        # 使能虚拟网口对
        self.vpp_host_pair_up()
        # 将需要抓包的网口的流量转发到虚拟网口对
        self.vpp_span_to_host_pair(self.span_if_list)
        # 启动vpp抓包进程
        self.tcpdump_start_capture()
        # 结束抓包进程后，清除环境
        self.clear_ctx()
        # 退出
        sys.exit(0)
        
    def flock_check(self):
        self.lock_file_fd = os.open(self.LOCK_FILE, os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(self.lock_file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except:
            print("another vtcpdump is running...")
            sys.exit(1)

    def vpp_process_check(self):
        if subprocess.run("vppctl show version >>/dev/null", shell=True).returncode != 0:
            print("vpp is not running!")
            sys.exit(2)
        return True

    def get_vpp_if_list(self):
        if_list_tmp = subprocess.Popen("vppctl show int | grep '^\w' | awk '{print $1}'", shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(if_list_tmp)):
            if_name = if_list_tmp[i].strip().decode()
            if self.vpp_if_is_dpdk(if_name) or self.vpp_if_is_bvi(if_name):
                self.if_list.append(if_name)

    def vpp_if_is_dpdk(self, if_name):
        if re.match(self.DPDK_PORT_FORMAT, if_name):
            return True
        else:
            return False

    def vpp_if_is_bvi(self, if_name):
        bvi_list = subprocess.Popen("vppctl show bridge-domain | awk '{print $13}' | grep -v BVI-Intf", shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(bvi_list)):
            bvi_list[i] = bvi_list[i].strip().decode()
        if if_name in bvi_list:
            return True
        else:
            return False
        
    def get_tcpdump_if_name(self, args):
        regex = re.compile("^-[a-zA-Z]*i$")
        for i in range(len(args)):
            if regex.fullmatch(args[i]):
                if i + 1 >= len(args):
                    break
                self.if_name = args[i+1]
                return
        print("Please use -i to specify interface, other argument are same as tcpdump.")
        for i in range(len(self.if_list)):
            print(f"{self.if_list[i]}")
        sys.exit(3)

    def get_span_if_list(self):
        if self.vpp_if_is_dpdk(self.if_name):
            self.span_if_list.append(self.if_name)
        elif self.vpp_if_is_bvi(self.if_name):
            self.span_if_list = self.vpp_if_list_in_bridge(self.if_name)
        else:
            print(f"Interface {self.if_name} is not a bvi or dpdk interface.")
            sys.exit(4)

    def vpp_if_list_in_bridge(self, bvi_if_name):
        bridge_domain_id = subprocess.Popen("vppctl show bridge-domain | grep %s | awk '{print $1}'"%bvi_if_name, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        if bridge_domain_id == []:
            return []
        bridge_domain_id = bridge_domain_id[0].strip().decode()
        cmd = "vppctl show bridge-domain %s detail | grep Interface -A 255 | awk '{print $1}' | egrep '%s'"%(bridge_domain_id, self.DPDK_PORT_FORMAT)
        if_list = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(if_list)):
            if_list[i] = if_list[i].strip().decode()
        return if_list

    def sighander_register(self):
        def sighander(*args, **kwargs):
            self.clear_ctx()
            sys.exit(0)
        signal.signal(signal.SIGINT, sighander)
        signal.signal(signal.SIGHUP, sighander)
        signal.signal(signal.SIGTERM, sighander)

    def create_host_pair(self):
        cmd = "ip link add name %s type veth peer name %s"%(self.PCAP_KERNEL_PORT, self.PCAP_VPP_PORT)
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s up"%self.PCAP_KERNEL_PORT
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s up"%self.PCAP_VPP_PORT
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    def delete_host_pair(self):
        cmd = "ip link set %s down > /dev/null 2>&1"%self.PCAP_KERNEL_PORT
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s down > /dev/null 2>&1"%self.PCAP_VPP_PORT
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link del %s > /dev/null 2>&1"%self.PCAP_KERNEL_PORT
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    def vpp_associate_to_host_pair(self):
        cmd = "vppctl create host-interface name %s"%self.PCAP_VPP_PORT
        retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_host_pair_up(self):
        cmd = "vppctl set int state host-%s up"%self.PCAP_VPP_PORT
        retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_host_pair_down(self):
        cmd = "vppctl set int state host-%s down"%self.PCAP_VPP_PORT
        retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_disassociate_from_host_pair(self):
        cmd = "vppctl delete host-interface name %s"%self.PCAP_VPP_PORT
        retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_span_to_host_pair(self, if_name_list):
        for if_name in if_name_list:
            cmd = "vppctl set interface span %s destination host-%s both"%(if_name, self.PCAP_VPP_PORT)
            retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
            if retcode != 0:
                return False
        return True
    
    def vpp_unspan_all_interfaces(self):
        cmd = "vppctl show int span | grep %s | awk '{print $1}'"%self.PCAP_VPP_PORT
        if_list = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(if_list)):
            if_list[i] = if_list[i].strip().decode()
        for if_name in if_list:
            cmd = "vppctl set interface span %s disable"%if_name
            retcode = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode

    def vpp_delete_host_pair(self):
        cmd = "ip link del %s"%self.PCAP_KERNEL_PORT
        ret_code = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).returncode
        if ret_code != 0:
            return False
        return True

    def tcpdump_get_cmd(self):
        tcpdump_cmd = "tcpdump "
        for i in range(len(sys.argv)):
            if i == 0:
                continue
            if sys.argv[i].startswith("-") and sys.argv[i].endswith("i") and i < len(sys.argv) - 1:
                sys.argv[i + 1] = self.PCAP_KERNEL_PORT
            tcpdump_cmd += sys.argv[i] + " "
        return tcpdump_cmd

    def tcpdump_start_capture(self):
        cmd = self.tcpdump_get_cmd()
        subprocess.run(cmd, shell=True)

    def clear_ctx(self):
        self.vpp_unspan_all_interfaces()
        self.vpp_host_pair_down()
        self.vpp_disassociate_from_host_pair()
        self.delete_host_pair()
    
Vtcpdump()
