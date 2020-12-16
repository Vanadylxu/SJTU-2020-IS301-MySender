import socket
import struct
from gmpy2 import bit_length

'''
标志位字段
CWR（Congestion Window Reduce）：拥塞窗口减少标志，用来表明它接收到了设置 ECE 标志的 TCP 包。并且，发送方收到消息之后，通过减小发送窗口的大小来降低发送速率。
ECE（ECN Echo）：用来在 TCP 三次握手时表明一个 TCP 端是具备 ECN 功能的。在数据传输过程中，它也用来表明接收到的 TCP 包的 IP 头部的 ECN 被设置为 11，即网络线路拥堵。
URG（Urgent）：表示本报文段中发送的数据是否包含紧急数据。URG=1 时表示有紧急数据。当 URG=1 时，后面的紧急指针字段才有效。
ACK：表示前面的确认号字段是否有效。ACK=1 时表示有效。只有当 ACK=1 时，前面的确认号字段才有效。TCP 规定，连接建立后，ACK 必须为 1。
PSH（Push）：告诉对方收到该报文段后是否立即把数据推送给上层。如果值为 1，表示应当立即把数据提交给上层，而不是缓存起来。
RST：表示是否重置连接。如果 RST=1，说明 TCP 连接出现了严重错误（如主机崩溃），必须释放连接，然后再重新建立连接。
SYN：在建立连接时使用，用来同步序号。当 SYN=1，ACK=0 时，表示这是一个请求建立连接的报文段；当 SYN=1，ACK=1 时，表示对方同意建立连接。SYN=1 时，说明这是一个请求建立连接或同意建立连接的报文。只有在前两次握手中 SYN 才为 1。
FIN：标记数据是否发送完毕。如果 FIN=1，表示数据已经发送完成，可以释放连接。
'''
class myTCP(object):
    def __init__(self, tcpmsg=None):
        self.src_port = tcpmsg['src_port']
        self.dst_port = tcpmsg['dst_port']
        self.src_ip = socket.inet_aton(tcpmsg['src_ip'])
        self.dst_ip = socket.inet_aton(tcpmsg['dst_ip'])
        self.seq_num = tcpmsg['seq_number']

        if self.seq_num == 0:
            self.ack_num = 0
        else:
            self.ack_num = tcpmsg['ack_number']  # the sequence number ready to receive next time
        self.head_len = 5  # 偏移量 至少20字节
        self.reserved = 0
        self.cwr = tcpmsg['CWR']
        self.ece = tcpmsg['ECE']
        self.urg = tcpmsg['URG']
        self.ack = tcpmsg['ACK']
        self.psh = tcpmsg['PSH']
        self.rst = tcpmsg['RST']
        self.syn = tcpmsg['SYN']
        self.fin = tcpmsg['FIN']
        self.win = tcpmsg['win_size']
        if self.urg == 0:
            self.urgent_pointer = 0
        else:
            self.urgent_pointer = tcpmsg['urgent_pointer']
        self.option = tcpmsg['option']
        self.option = self.option + ((4-len(self.option)%4) % 4)* b'\x00'
        self.head_len += len(self.option) // 4
        self.data = tcpmsg['data']

    def Check_sum(self,data):
        length = len(data)
        result = 0
        for i in range(0, length - length % 2, 2):
            result += (data[i] << 8) + data[i + 1]
        if length % 2 == 1:
            result += data[length - 1]
        while result >> 16:
            result = (result & 0xffff) + result >> 16
        result = (~result) & 0xffff
        return result

    # construct the whole TCP message
    def pack(self):
        # the length of header and some flags compose 2 bytes
        data_flags = (self.head_len << 12) + (self.cwr << 7)+ (self.ece << 6)+ (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + (self.fin)
        header = struct.pack(">HHLLHHHH", self.src_port, self.dst_port, self.seq_num, self.ack_num, data_flags, self.win, 0, self.urgent_pointer)
        self.data += ((4 - (len(self.data) % 4)) % 4) * (b'\x00')
        len_tcp = int(self.head_len) * 4 + int(len(self.data))
        ip_header = struct.pack(">4s4sBBH",self.src_ip, self.dst_ip, 0,0x06, len_tcp)
        self.head_sum = self.Check_sum(ip_header + header + self.option + self.data)
        header = struct.pack(">HHLLHHHH", self.src_port, self.dst_port, self.seq_num, self.ack_num, data_flags, self.win, self.head_sum, self.urgent_pointer)
        header = header + self.option
        msg = header + self.data
        print(msg)
        return msg

    def send(self):
        tcpmsg = self.pack()
        mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mysocket.bind((socket.inet_ntoa(self.src_ip),self.src_port))
        mysocket.settimeout(2)
        mysocket.connect((socket.inet_ntoa(self.dst_ip), self.dst_port))
        try:
            mysocket.send(tcpmsg)
            return True
        except:
            mysocket.close()
            return False