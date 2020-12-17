
from scapy.all import *
''' ARP报文格式
硬件类型：占两字节，表示ARP报文可以在哪种类型的网络上传输，值为1时表示为以太网地址。
上层协议类型：占两字节，表示硬件地址要映射的协议地址类型，映射IP地址时的值为0x0800。
MAC地址长度：占一字节，标识MAC地址长度，以字节为单位，此处为6。
IP协议地址长度：占一字节，标识IP得知长度，以字节为单位，此处为4。
操作类型：占2字节，指定本次ARP报文类型。1标识ARP请求报文，2标识ARP应答报文。
源MAC地址：占6字节，标识发送设备的硬件地址。
源IP地址：占4字节，标识发送方设备的IP地址。
目的MAC地址：占6字节，表示接收方设备的硬件地址，在请求报文中该字段值全为0，表示任意地址，因为现在不知道这个MAC地址。
目的IP地址：占4字节，表示接受方的IP地址。
'''
BROADCAST = 'ff:ff:ff:ff:ff:ff'
class myARP(object):
    def __init__(self, msg=None):
        # 请求时目标mac地址应为'00:00:00:00:00:00'
        # in other situation, they should be equal
        self.src_mac = msg['src_mac']
        self.src_ip = msg['src_ip']
        self.dst_mac = msg['dst_mac']
        self.dst_ip = msg['dst_ip']
        self.HARDWARE_TYPE = msg['HARDWARE_TYPE']
        self.PROTOCOL_TYPE = msg['PROTOCOL_TYPE']
        self.HARDWARE_LEN = msg['HARDWARE_LEN']
        self.PROTOCOL_LEN = msg['PROTOCOL_LEN']
        self.type = msg['type']#应该是op
        print(msg)

    def send(self):
        myarp = ARP()

        myarp.psrc = self.src_ip
        myarp.pdst = self.dst_ip
        myarp.op = self.type
        myarp.hwdst = self.dst_mac
        myarp.hwsrc = self.src_mac
        send(myarp)
        return True
