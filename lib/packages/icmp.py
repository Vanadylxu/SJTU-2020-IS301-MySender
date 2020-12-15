import struct
import socket
# 头部构成： type (8), code (8), checksum (16), id (16), sequence (16)
class myICMP(object):
    def __init__(self,msg=None):
        if not msg:
            return
        else:
            self.type = msg["type"]
            self.code = msg["code"]
            self.id = msg["id"]
            self.seq = msg["seq"]
            self.data = msg["data"]
            self.dst_ip = msg["dst_ip"]
            self.src_ip = msg["src_ip"]

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

    def pack(self,data):#打包报文

        header = struct.pack('>bbHHh',self.type,self.code, 0, self.id, self.seq)
        data = struct.pack('{}s'.format(len(data)), data)
        print(data)
        self.head_sum = self.checkSum(header+data)
        header = struct.pack('>bbHHh',self.type,self.code,self.head_sum,self.id, self.seq)
        packet = header + data
        return packet

    def send(self):
        msg = self.pack(self.data)

        mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname("icmp"))
        mysocket.settimeout(3)
        ip= self.dst_ip
        try:
            mysocket.sendto(msg, (ip, 1))
            reply = mysocket.recvfrom(1024)
            if reply is not None:
                mysocket.close()
                print(reply)
                return True
        except:
            mysocket.close()
            return False
