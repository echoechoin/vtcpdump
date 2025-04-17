#!/usr/bin/python3
import re
import os
import sys
import shlex
import fcntl
import signal
import pathlib
import subprocess


class Vtcpdump(object):
    """
    Using tcpdump to capture packets on vpp interfaces(only dpdk interfaces and bridge-domain interfaces).
    """
    DPDK_PORT_FORMAT = "^[A-Za-z0-9]*Ethernet[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$"
    PCAP_KERNEL_PORT_FORMAT = "vtd0_%s"
    PCAP_VPP_PORT_FORMAT = "vtd1_%s"
    LOCK_FILE_DIR = "/tmp/app/ngrayvpp/"
    LOCK_FILE_FORMAT = f"{LOCK_FILE_DIR}vtcpdump_%s.lock"
    VPPCTL = "vppctl"

    def __init__(self):
        self.debug = False
        self.pid = os.getpid()
        self.pcap_kernel_port = self.PCAP_KERNEL_PORT_FORMAT % str(self.pid)
        self.pcap_vpp_port = self.PCAP_VPP_PORT_FORMAT % str(self.pid)
        self.if_list = []
        self.bvi_list = {}
        self.span_if_list = []
        self.if_name = None
        self.lock_file_name = self.LOCK_FILE_FORMAT % self.pid
        self.lock_file = None
        self.flock_check()
        self.vpp_process_check()
        self.get_vpp_if_list()
        self.get_vpp_bvi_list()
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

    def run_command(self, cmd, error_msg, exit_code):
        cmd = shlex.split(cmd)
        if len(cmd) == 0:
            return
        if cmd[0] == "vppctl":
            cmd[0] = self.VPPCTL
        cmd = ["ip", "netns", "exec", "ns-data-plane"] + cmd
        if self.debug:
            print(f"cmd: {' '.join(cmd)}")

        output = subprocess.run(
            cmd, stdout=subprocess.PIPE)

        if output.returncode != 0 and error_msg:
            print(f"{error_msg}")
            self.exit(exit_code)

        return output.stdout.decode()

    def exit(self, exit_code):
        if self.lock_file != None:
            self.lock_file.close()
        sys.exit(exit_code)

    def flock_check(self):
        for lock_file_name in pathlib.Path(self.LOCK_FILE_DIR).glob("vtcpdump_*.lock"):
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
            print(f"confict with other vtcpdump process! {self.lock_file_name} is locked!(current pid: {self.pid})")
            self.exit(1)

    def vpp_process_check(self):
        output = self.run_command("vppctl show version", None, 0)
        if "vpp" not in output:
            print("vpp is not running!")
            self.exit(1)
        return True

    def get_vpp_if_list(self):
        lines = self.run_command("vppctl show int", "vppctl show int failed!", 1).splitlines()
        for i in range(len(lines)):
            if_name = lines[i].split()[0].strip()
            if self.vpp_if_is_dpdk(if_name) or self.vpp_if_is_bvi(if_name):
                self.if_list.append(if_name)
    
    def get_vpp_bvi_list(self):
        lines = self.run_command("vppctl show bridge-domain", "vppctl show bridge-domain failed!", 1).splitlines()
        for line in lines:
            line = line.split()
            if "BVI-Intf" in line or len(line) != 13:
                continue
            self.bvi_list[line[-1]] = line[0]

    def vpp_if_is_dpdk(self, if_name):
        if re.match(self.DPDK_PORT_FORMAT, if_name):
            return True
        else:
            return False 

    def vpp_if_is_bvi(self, if_name):
        if if_name in self.bvi_list.keys():
            return True
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
        for k, _ in self.bvi_list.items():
            print(f"{k}")
        self.exit(1)

    def get_span_if_list(self):
        if self.vpp_if_is_dpdk(self.if_name):
            self.span_if_list.append(self.if_name)
        elif self.vpp_if_is_bvi(self.if_name):
            self.span_if_list = self.vpp_if_list_in_bridge(self.if_name)
        else:
            print(f"Interface {self.if_name} is not a bvi or dpdk interface.")
            self.exit(1)

    def vpp_if_list_in_bridge(self, bvi_if_name):
        if_list = []
        if bvi_if_name not in self.bvi_list.keys():
            print(f"Interface {bvi_if_name} is not a bvi interface.")
            self.exit(1)
        lines = self.run_command(f"vppctl show bridge-domain {self.bvi_list[bvi_if_name]} detail", 
                                f"vppctl show bridge-domain {self.bvi_list[bvi_if_name]} detail failed!", 1).splitlines()
        for line in lines:
            line = line.split()
            if len(line) != 7:
                continue
            if re.match(self.DPDK_PORT_FORMAT, line[0]):
                if_list.append(line[0])
        return if_list

    def sighander_register(self):
        def sighander(*args, **kwargs):
            self.clear_ctx(self.pid)
            self.exit(0)
        signal.signal(signal.SIGINT, sighander)
        signal.signal(signal.SIGHUP, sighander)
        signal.signal(signal.SIGTERM, sighander)

    def create_host_pair(self):
        cmd = f"ip link add name {self.pcap_kernel_port} type veth peer name {self.pcap_vpp_port}"
        self.run_command(cmd, f"ip link add name {self.pcap_kernel_port} type veth peer name {self.pcap_vpp_port} failed!", 1)
        cmd = f"ip link set {self.pcap_kernel_port} up"
        self.run_command(cmd, f"ip link set {self.pcap_kernel_port} up failed!", 1)
        cmd = f"ip link set {self.pcap_vpp_port} up"
        self.run_command(cmd, f"ip link set {self.pcap_vpp_port} up failed!", 1)

    def delete_host_pair(self, pid):
        cmd = f"ip link set {self.PCAP_KERNEL_PORT_FORMAT % pid} down"
        self.run_command(cmd, None, 0)
        cmd = f"ip link set {self.PCAP_VPP_PORT_FORMAT % pid} down"
        self.run_command(cmd, None, 0)
        cmd = f"ip link del {self.PCAP_KERNEL_PORT_FORMAT % pid}"
        self.run_command(cmd, None, 0)

    def vpp_associate_to_host_pair(self):
        cmd = f"vppctl create host-interface name {self.pcap_vpp_port}"
        self.run_command(cmd, f"vppctl create host-interface name {self.pcap_vpp_port} failed!", 1)
        return True

    def vpp_disassociate_from_host_pair(self, pid):
        cmd = f"vppctl delete host-interface name {self.PCAP_VPP_PORT_FORMAT % pid}"
        self.run_command(cmd, None, 0)
        return True

    def vpp_host_pair_up(self):
        cmd = f"vppctl set int state host-{self.pcap_vpp_port} up"
        self.run_command(cmd, f"vppctl set int state host-{self.pcap_vpp_port} up failed!", 1)
        return True

    def vpp_host_pair_down(self, pid):
        cmd = f"vppctl set int state host-{self.PCAP_VPP_PORT_FORMAT % pid} down"
        self.run_command(cmd, None, 0)
        return True

    def vpp_span_to_host_pair(self, if_name_list):
        for if_name in if_name_list:
            cmd = f"vppctl set interface span {if_name} destination host-{self.pcap_vpp_port} both"
            self.run_command(cmd, f"vppctl set interface span {if_name} destination host-{self.pcap_vpp_port} both failed!", 1)
        return True

    def vpp_unspan_interfaces(self, pid):
        port_format = shlex.quote(self.PCAP_VPP_PORT_FORMAT % pid)
        lines = self.run_command("vppctl show int span", None, 0).splitlines()
        if_list = [line.split()[0] for line in lines if port_format in line]
        for i in range(len(if_list)):
            if_list[i] = if_list[i].strip()
        for if_name in if_list:
            cmd = f"vppctl set interface span {if_name} disable"
            self.run_command(cmd, None, 0)

    def tcpdump_get_cmd(self):
        tcpdump_cmd = "tcpdump"
        for i in range(len(sys.argv)):
            if i == 0:
                continue
            if i == 1 and sys.argv[i] == "debug":
                self.debug = True
                continue
            if sys.argv[i].startswith("-") and sys.argv[i].endswith("i") and i < len(sys.argv) - 1:
                sys.argv[i + 1] = self.pcap_kernel_port
            tcpdump_cmd = f"{tcpdump_cmd} {sys.argv[i]}"
        return tcpdump_cmd

    def tcpdump_start_capture(self):
        cmd = self.tcpdump_get_cmd()
        subprocess.run(shlex.split(cmd))

    def clear_ctx(self, pid):
        self.vpp_unspan_interfaces(pid)
        self.vpp_host_pair_down(pid)
        self.vpp_disassociate_from_host_pair(pid)
        self.delete_host_pair(pid)
        if self.debug:
            print(f"delete lock file: {self.LOCK_FILE_FORMAT % str(pid)}")
        os.unlink(self.LOCK_FILE_FORMAT % str(pid))

if __name__ == "__main__":
    Vtcpdump()
