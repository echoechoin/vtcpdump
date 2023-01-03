#!/usr/bin/python3
import re
import os
import sys
import fcntl
import signal
import pathlib
import subprocess


class Vtcpdump(object):
    """
    Using tcpdump to capture packets on vpp interfaces(only dpdk interfaces and bridge-domain interfaces).
    FIXME: can not filter packets by url (tcpdump.py -ni <interface> host <url>) because of the problem about DNS.
    """
    DPDK_PORT_FORMAT = "^[A-Za-z0-9]*Ethernet[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$"
    PCAP_KERNEL_PORT_FORMAT = "rayp0_%s"
    PCAP_VPP_PORT_FORMAT = "rayp1_%s"
    LOCK_FILE_FORMAT = "/tmp/vtcpdump_%s.lock"

    def __init__(self):
        self.pid = os.getpid()
        self.pcap_kernel_port = self.PCAP_KERNEL_PORT_FORMAT % str(self.pid)
        self.pcap_vpp_port = self.PCAP_VPP_PORT_FORMAT % str(self.pid)
        self.if_list = []
        self.span_if_list = []
        self.if_name = None
        self.lock_file_name = self.LOCK_FILE_FORMAT % self.pid
        self.lock_file = None
        self.flock_check()
        self.vpp_process_check()
        self.get_vpp_if_list()
        self.get_tcpdump_if_name(sys.argv[1:])
        # get interfaces that need to map to the veth device (bridge may have more than one interface that need to map)
        self.get_span_if_list()
        self.sighander_register()
        # let the network packets forward to the veth device
        self.create_host_pair()
        self.vpp_associate_to_host_pair()
        self.vpp_host_pair_up()
        self.vpp_span_to_host_pair(self.span_if_list)
        self.tcpdump_start_capture()
        if self.lock_file != None:
            self.lock_file.close()
        self.clear_ctx(self.pid)
        sys.exit(0)

    def get_pid_from_lock_file(self, lock_file_name):
        pid = lock_file_name.split("_")[-1].split(".")[0]
        if re.match("^[0-9]+$", pid):
            return int(pid)
        return 0

    def flock_check(self):
        for lock_file_name in pathlib.Path("/tmp").glob("vtcpdump_*.lock"):
            lock_file_name = str(lock_file_name)
            try:
                pid = self.get_pid_from_lock_file(lock_file_name)
                fd = open(lock_file_name, "w")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.clear_ctx(pid)
                fd.close()
                os.unlink(lock_file_name)
            except:
                continue
        self.lock_file = open(self.lock_file_name, "w")
        try:
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except:
            print("confict with other vtcpdump process! %s is locked!(current pid: %s)" % (
                self.lock_file_name, self.pid))
            sys.exit(1)

    def vpp_process_check(self):
        if subprocess.run("vppctl show version >>/dev/null", shell=True).returncode != 0:
            print("vpp is not running!")
            sys.exit(2)
        return True

    def get_vpp_if_list(self):
        if_list_tmp = subprocess.Popen(
            "vppctl show int | grep '^\w' | awk '{print $1}'", shell=True, stdout=subprocess.PIPE).stdout.readlines()
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
        bvi_list = subprocess.Popen(
            "vppctl show bridge-domain | awk '{print $13}' | grep -v BVI-Intf", shell=True, stdout=subprocess.PIPE).stdout.readlines()
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
        bridge_domain_id = subprocess.Popen(
            "vppctl show bridge-domain | grep %s | awk '{print $1}'" % bvi_if_name, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        if bridge_domain_id == []:
            return []
        bridge_domain_id = bridge_domain_id[0].strip().decode()
        cmd = "vppctl show bridge-domain %s detail | grep Interface -A 255 | awk '{print $1}' | egrep '%s'" % (
            bridge_domain_id, self.DPDK_PORT_FORMAT)
        if_list = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(if_list)):
            if_list[i] = if_list[i].strip().decode()
        return if_list

    def sighander_register(self):
        def sighander(*args, **kwargs):
            self.clear_ctx(self.pid)
            sys.exit(0)
        signal.signal(signal.SIGINT, sighander)
        signal.signal(signal.SIGHUP, sighander)
        signal.signal(signal.SIGTERM, sighander)

    def create_host_pair(self):
        cmd = "ip link add name %s type veth peer name %s" % (
            self.pcap_kernel_port, self.pcap_vpp_port)
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s up" % self.pcap_kernel_port
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s up" % self.pcap_vpp_port
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    def delete_host_pair(self, pid):
        cmd = "ip link set %s down > /dev/null 2>&1" % (
            self.PCAP_KERNEL_PORT_FORMAT % pid)
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link set %s down > /dev/null 2>&1" % (
            self.PCAP_VPP_PORT_FORMAT % pid)
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        cmd = "ip link del %s > /dev/null 2>&1" % (
            self.PCAP_KERNEL_PORT_FORMAT % pid)
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    def vpp_associate_to_host_pair(self):
        cmd = "vppctl create host-interface name %s" % self.pcap_vpp_port
        retcode = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_disassociate_from_host_pair(self, pid):
        cmd = "vppctl delete host-interface name %s" % (
            self.PCAP_VPP_PORT_FORMAT % pid)
        retcode = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_host_pair_up(self):
        cmd = "vppctl set int state host-%s up" % self.pcap_vpp_port
        retcode = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_host_pair_down(self, pid):
        cmd = "vppctl set int state host-%s down" % (
            self.PCAP_VPP_PORT_FORMAT % pid)
        retcode = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE).returncode
        if retcode != 0:
            return False
        return True

    def vpp_span_to_host_pair(self, if_name_list):
        for if_name in if_name_list:
            cmd = "vppctl set interface span %s destination host-%s both" % (
                if_name, self.pcap_vpp_port)
            retcode = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE).returncode
            if retcode != 0:
                return False
        return True

    def vpp_unspan_interfaces(self, pid):
        cmd = "vppctl show int span | grep %s | awk '{print $1}'" % (self.PCAP_VPP_PORT_FORMAT % str(
            pid))
        if_list = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE).stdout.readlines()
        for i in range(len(if_list)):
            if_list[i] = if_list[i].strip().decode()
        for if_name in if_list:
            cmd = "vppctl set interface span %s disable" % if_name
            retcode = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE).returncode
            if retcode != 0:
                print("vppctl set interface span %s disable failed" % if_name)
                sys.exit(5)

    def tcpdump_get_cmd(self):
        tcpdump_cmd = "tcpdump "
        for i in range(len(sys.argv)):
            if i == 0:
                continue
            if sys.argv[i].startswith("-") and sys.argv[i].endswith("i") and i < len(sys.argv) - 1:
                sys.argv[i + 1] = self.pcap_kernel_port
            tcpdump_cmd += sys.argv[i] + " "
        return tcpdump_cmd

    def tcpdump_start_capture(self):
        cmd = self.tcpdump_get_cmd()
        subprocess.run(cmd, shell=True)

    def clear_ctx(self, pid):
        self.vpp_unspan_interfaces(pid)
        self.vpp_host_pair_down(pid)
        self.vpp_disassociate_from_host_pair(pid)
        self.delete_host_pair(pid)
        os.unlink(self.LOCK_FILE_FORMAT % str(pid))

Vtcpdump()
