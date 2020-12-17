import struct
import socket

typedict = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

class myIP(object):
    def __init__(self, msg=None):
        self.version = msg['version']
        self.head_len = 5 #最小值为20字节
        self.ser_type = msg['type']
        self.id = msg['identifier']
        self.flag = msg['DF'] << 1 + msg["MF"]
        self.frag_off = 0
        self.ttl = msg['ttl']
        self.proto = msg['type']
        self.src_ip = msg['src_ip']
        self.dst_ip = msg['dst_ip']

        self.option = msg['option'] + ((4 - len(msg["option"]) % 4) % 4) * b'\x00'
        self.head_len += len(self.option) // 4
        self.data = msg['data'] + ((4-len(msg["data"])%4) % 4 )*b'\x00' #外面的模4其实可以不要因为data不可以为空
        self.total_len = (self.head_len * 4) + len(self.data)
        print(msg)



    def checkSum(self,str):#educoder写过
        csum = 0
        if len(str)%2==0:
            countTo = len(str)
        else:
            countTo = len(str) - 1
        count = 0
        while count < countTo:
            thisVal = str[count + 1] * 256 + str[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2
        if countTo < len(str):
            csum = csum + str[len(str) - 1]
            csum = csum & 0xffffffff
        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    # construct the whole ip message
    def pack(self):
        # ip_version and head_length compose 1 byte
        ip_ihl_ver = (self.version << 4) + self.head_len
        # flags and frag_offsite compose 2 bytes
        flag_offset = (self.flag << 13) + self.frag_off
        header = struct.pack("!BBHHHBBH4s4s",ip_ihl_ver, self.ser_type, self.total_len, self.id, flag_offset, self.ttl, self.proto, 0, socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))

        self.head_sum = self.checkSum(header + self.option)
        header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, self.ser_type, self.total_len, self.id, flag_offset, self.ttl, self.proto, self.head_sum, socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        packet = header + self.data
        return packet

    def send(self):
        msg = self.pack()
        if self.ser_type == 1 or self.ser_type == 17:
            mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname(typedict[self.ser_type]))
            mysocket.settimeout(2)
            mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            mysocket.connect((self.dst_ip, 10086))#随便选的端口
            try:
                mysocket.send(msg)
                mysocket.close()
                return True
            except:
                mysocket.close()
                return False
        else:
            mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mysocket.bind((self.src_ip, 10086))
            mysocket.settimeout(2)
            mysocket.connect((self.dst_ip, 80))
            try:
                mysocket.send(msg)
                return True
            except:
                mysocket.close()
                return False