# My Sender 文档

## ICMP实现

可以成功ping外网并得到回复，此前难以得到回复，wireshark会提示no response found，估计是因为id默认值为0或数据段为空所致，加入后问题解决，成功实现（Q的编码为0x51）。

若不能收到回复，请检测发送报文的类型是否为Request！！

![image-20201215113044187](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201215113044187.png)

![image-20201215113218319](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201215113218319.png)



## ARP实现

成功图如下。由于网上有关ARP的资料太少，只好用了另一个包scapy。

![image-20201215172545515](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201215172545515.png)



## UDP实现

![image-20201215202618187](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201215202618187.png)

![image-20201215202248579](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201215202248579.png)

## TCP实现

![image-20201216171141218](C:\Users\a\AppData\Roaming\Typora\typora-user-images\image-20201216171141218.png)