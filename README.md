# vtcpdump

using tcpdump to capture packets from vpp interface.

## principles

using veth device to receive packets from vpp interface. then using tcpdump to capture packets.

## usages

./vtcpdump.py -nvi GigabitEthernet0/0/1 (just same as tcpdump)

## supported vpp version

I've just tested this on vpp version 22.02, may be it works on other versions.

have fun ! ! 😆😆
