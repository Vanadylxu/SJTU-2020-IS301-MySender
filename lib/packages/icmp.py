import struct
import socket

class ICMP(object):
    def __init__(self):

        return

    def checksum(str):#参考educoder代码
        csum = 0
        countTo = (len(str) / 2) * 2
        count = 0
        while count < countTo:
            thisVal = str[count + 1] * 256 + str[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2
        if countTo < len(str):
            csum = csum + str[len(str) - 1].decode()
            csum = csum & 0xffffffff
        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer