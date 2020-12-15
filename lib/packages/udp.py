import socket
import struct

class myUDP(object):
    def __init__(self, udpmsg=None):
        self.src_ip = socket.inet_aton(udpmsg['src_ip'])
        self.dst_ip = socket.inet_aton(udpmsg['dst_ip'])
        self.src_port = udpmsg['src_port']
        self.dst_port = udpmsg['dst_port']
        self.data = udpmsg['data']
        self.checksum = 0
        self.length = 8 + len(self.data)

        # calculate the check sum of header
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
    # construct the whole UDP message
    def pack(self):
        Header = struct.pack(">4s4s6H",self.src_ip,self.dst_ip, 17, self.length, self.src_port, self.dst_port, self.length, 0)
        packet = Header + self.data
        self.checksum = self.checkSum(packet)
        packet = struct.pack(">4H", self.src_port, self.dst_port, self.length, self.checksum)
        packet = packet + self.data
        return packet

    def send(self):
        udpmsg = self.pack()
        mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        mysocket.settimeout(3)
        try:
            mysocket.sendto(udpmsg, (socket.inet_ntoa(self.dst_ip), self.dst_port))
            reply = mysocket.recvfrom(1024)
            if reply is not None:
                mysocket.close()
                #print(reply)
                return True
        except:
            mysocket.close()
            return False

    #pass