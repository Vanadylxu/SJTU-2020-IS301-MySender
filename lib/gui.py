import tkinter as tk
import tkinter.font as tkFont
from tkinter import ttk
import tkinter.messagebox
import webbrowser
from lib.packages.icmp import myICMP
from lib.packages.ip import myIP
from lib.packages.tcp import myTCP
from lib.packages.udp import myUDP
from lib.packages.arp import myARP
from lib.misc import *
icmp_number = 0
arp_number = 0
udp_number = 0
tcp_number = 0
ip_number = 0
class Window:
    def __init__(self):
        self.TITLE = "MySender"
        self.WIDTH = 900
        self.HEIGHT = 600

        # Initial GUI
    def initialGUI(self):
        def ip_send():
            iptypedict = {"ICMP": 1 , "TCP": 6, "UDP": 17  }
            global ip_number
            ipmsg = {}
            ipmsg['data'] = (ip_data.get()).encode()
            ipmsg['version'] = ipVersion.get()
            try:
                ipmsg['DF'] = DF.get()
                check = int(ipmsg['DF'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check DF,flags is either 1 or 0!")
                return
            try:
                ipmsg['MF'] = MF.get()
                check = int(ipmsg['MF'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check MF,flags is either 1 or 0!")
                return
            try:
                ipmsg['ttl'] = ttl.get()
                check = int(ipmsg['ttl'])
                assert check <= 255
            except:
                tk.messagebox.showerror(title="error", message="TTL is an integer less than 256!")
                return
            try:
                ipmsg['identifier'] = ip_id.get()
                check = int(ipmsg['identifier'])
            except:
                tk.messagebox.showerror(title="error", message="Please check id!")
            try:
                ipmsg['type'] = iptypedict[ipupType.get()]
            except:
                tk.messagebox.showerror(title="error", message="Please select a upper protocol type!")
            try:
                ipmsg['option'] = bytes.fromhex((opt.get()))
            except:
                tk.messagebox.showerror(title="error", message="Options must be hex string!")
                return
            ipmsg['src_ip'] = ip_srcip.get()
            if not check_ip(ipmsg['src_ip']):
                tk.messagebox.showerror(title="error", message="Please check source ip address!")
                return
            ipmsg['dst_ip'] = ip_dstip.get()
            if not check_ip(ipmsg['dst_ip']):
                tk.messagebox.showerror(title="error", message="Please check destination ip address!")
                return

            ip_pack = myIP(ipmsg)
            if ip_pack.send():
                tk.messagebox.showinfo(title="info", message="send successfully!")
            else:
                tk.messagebox.showerror(title="error", message="IP package send error please contact author")
            ipDetail.append(ipmsg)
            ip_number += 1
            iplog.insert('', ip_number, values=(ip_number, ipmsg['src_ip'], ipmsg['dst_ip']))

        def ip_show(event):
            typedict = { 1: "ICMP", 6: "TCP",  17: "UDP"}
            ipDetailText.configure(state="normal")
            ipDetailText.delete(1.0, tk.END)
            for item in iplog.selection():
                item_text = iplog.item(item, "values")
                print(item_text)
                print(ipDetail[int(item_text[0]) - 1])
                ipDetailText.insert("insert", "number:" + item_text[0] + '\n')
                ipDetailText.insert("end", "data:" + str(ipDetail[int(item_text[0]) - 1]["data"]) + '\n')
                ipDetailText.insert("end", "Upper Protocol:" + typedict[ipDetail[int(item_text[0]) - 1]["type"]] + '\n')
                ipDetailText.insert("end", "destination ip address:" + ipDetail[int(item_text[0]) - 1]["dst_ip"] + '\n')
                ipDetailText.insert("end", "source ip address:" + ipDetail[int(item_text[0]) - 1]["src_ip"] + '\n')
                ipDetailText.insert("end", "DF:" + str(ipDetail[int(item_text[0]) - 1]["DF"]) + '\n')
                ipDetailText.insert("end", "MF:" + str(ipDetail[int(item_text[0]) - 1]["MF"]) + '\n')
                ipDetailText.insert("end", "Identifier:" + str(ipDetail[int(item_text[0]) - 1]["identifier"]) + '\n')
                ipDetailText.insert("end", "Time to live:" + str(ipDetail[int(item_text[0]) - 1]["ttl"]) + '\n')
                ipDetailText.configure(state="disabled")

        def tcp_send():
            global tcp_number
            tcpmsg = {}
            tcpmsg['data'] = (tcp_data.get()).encode()
            try:
                tcpmsg['CWR'] = CWR.get()
                check = int(tcpmsg['CWR'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check CWR,flags is either 1 or 0!")
                return
            try:
                tcpmsg['ECE'] = ECE.get()
                check = int(tcpmsg['ECE'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check ECE,flags is either 1 or 0!")
                return
            try:
                tcpmsg['URG'] = URG.get()
                check = int(tcpmsg['URG'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check URG,flags is either 1 or 0!")
                return
            try:
                tcpmsg['ACK'] = ACK.get()
                check = int(tcpmsg['ACK'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check ACK,flags is either 1 or 0!")
                return
            try:
                tcpmsg['PSH'] = PSH.get()
                check = int(tcpmsg['PSH'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check PSH,flags is either 1 or 0!")
                return
            try:
                tcpmsg['RST'] = RST.get()
                check = int(tcpmsg['RST'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check RST,flags is either 1 or 0!")
                return
            try:
                tcpmsg['SYN'] = SYN.get()
                check = int(tcpmsg['SYN'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check SYN,flags is either 1 or 0!")
                return
            try:
                tcpmsg['FIN'] = FIN.get()
                check = int(tcpmsg['ACK'])
                assert check <= 1
            except:
                tk.messagebox.showerror(title="error", message="Please check FIN,flags is either 1 or 0!")
                return
            try:
                tcpmsg['urgent_pointer'] = urgent_pointer.get()
                check = int(tcpmsg['urgent_pointer'])
            except:
                tk.messagebox.showerror(title="error", message="Please check urgent_pointer!")
                return
            try:
                tcpmsg['win_size'] = win_size.get()
                check = int(tcpmsg['win_size'])
            except:
                tk.messagebox.showerror(title="error", message="Please check urgent_pointer!")
            try:
                tcpmsg['seq_number'] = seq_num.get()
                check = int(tcpmsg['seq_number'])
            except:
                tk.messagebox.showerror(title="error", message="Please check sequence number!")
                return
            try:
                tcpmsg['ack_number'] = ack_num.get()
                check = int(tcpmsg['ack_number'])
            except:
                tk.messagebox.showerror(title="error", message="Please check acknowledge number!")
                return
            try:
                tcpmsg['option'] = bytes.fromhex((opt.get()))
            except:
                tk.messagebox.showerror(title="error", message="Options must be hex string!")
                return
            try:
                tcpmsg['src_port'] = tcp_sport.get()
                check = int(tcpmsg['src_port'])
                assert check <= 65535
            except:
                tk.messagebox.showerror(title="error", message="Please check source port!")
                return
            try:
                tcpmsg['dst_port'] = tcp_dport.get()
                check = int(tcpmsg['dst_port'])
                assert check <= 65535
            except:
                tk.messagebox.showerror(title="error", message="Please check destination port!")
                return
            tcpmsg['src_ip'] = tcp_srcip.get()
            if not check_ip(tcpmsg['src_ip']):
                tk.messagebox.showerror(title="error", message="Please check source ip address!")
                return
            tcpmsg['dst_ip'] = tcp_dstip.get()
            if not check_ip(tcpmsg['dst_ip']):
                tk.messagebox.showerror(title="error", message="Please check destination ip address!")
                return
            tcp_pack = myTCP(tcpmsg)
            if tcp_pack.send():
                tk.messagebox.showinfo(title="info", message="send successfully!")
            else:
                tk.messagebox.showerror(title="error", message="TCP package send error please contact author")
            tcpmsg['flags'] = bin((CWR.get() << 7) + (ECE.get() << 6) + (URG.get() << 5) + (ACK.get() << 4) + (PSH.get() << 3) + (RST.get() << 2) + (SYN.get() << 1) + FIN.get())
            tcpDetail.append(tcpmsg)
            tcp_number += 1
            tcplog.insert('', tcp_number, values=(tcp_number, tcpmsg['src_ip'], tcpmsg['dst_ip'], tcpmsg['src_port'], tcpmsg['dst_port']))
        def tcp_show(event):
            tcpDetailText.configure(state="normal")
            tcpDetailText.delete(1.0, tk.END)
            for item in tcplog.selection():
                item_text = tcplog.item(item, "values")
                print(item_text)
                print(tcpDetail[int(item_text[0]) - 1])
                tcpDetailText.insert("insert", "number:" + item_text[0] + '\n')
                tcpDetailText.insert("end", "data:" + str(tcpDetail[int(item_text[0]) - 1]["data"]) + '\n')
                tcpDetailText.insert("end", "destination ip address:" + tcpDetail[int(item_text[0]) - 1]["dst_ip"] + '\n')
                tcpDetailText.insert("end", "source ip address:" + tcpDetail[int(item_text[0]) - 1]["src_ip"] + '\n')
                tcpDetailText.insert("end", "destination port:" + str(tcpDetail[int(item_text[0]) - 1]["dst_port"]) + '\n')
                tcpDetailText.insert("end", "source port:" + str(tcpDetail[int(item_text[0]) - 1]["src_port"]) + '\n')
                tcpDetailText.insert("end", "flags:" + str(tcpDetail[int(item_text[0]) - 1]["flags"]) + '\n')
                tcpDetailText.configure(state="disabled")

        def udp_send():
            global udp_number
            udpmsg = {}
            udpmsg['data'] = (udp_data.get()).encode()
            try:
                udpmsg['src_port'] = udp_sport.get()
                check = int(udpmsg['src_port'])
                assert check <= 65535
            except:
                tk.messagebox.showerror(title="error", message="Please check source port!")
                return
            try:
                udpmsg['dst_port'] = udp_dport.get()
                check = int(udpmsg['dst_port'])
                assert check <= 65535
            except:
                tk.messagebox.showerror(title="error", message="Please check destination port!")
                return
            udpmsg['src_ip'] = udp_srcip.get()
            if not check_ip(udpmsg['src_ip']):
                tk.messagebox.showerror(title="error", message="Please check source ip address!")
                return
            udpmsg['dst_ip'] = udp_dstip.get()
            if not check_ip(udpmsg['dst_ip']):
                tk.messagebox.showerror(title="error", message="Please check destination ip address!")
                return
            udp_pack = myUDP(udpmsg)
            if udp_pack.send():
                tk.messagebox.showinfo(title="info", message="send successfully!")
            else:
                tk.messagebox.showerror(title="error", message="reply not received")
            udpDetail.append(udpmsg)
            udp_number += 1
            print(udp_number)
            udplog.insert('', udp_number,values=(udp_number, udpmsg['src_ip'], udpmsg['dst_ip'], udpmsg['src_port'], udpmsg['dst_port']))
        def udp_show(event):
            udpDetailText.configure(state="normal")
            udpDetailText.delete(1.0, tk.END)
            for item in udplog.selection():
                item_text = udplog.item(item, "values")
                print(item_text)
                print(udpDetail[int(item_text[0])-1])
                udpDetailText.insert("insert", "number:" + item_text[0] + '\n')
                udpDetailText.insert("end", "data:" + str(udpDetail[int(item_text[0])-1]["data"]) + '\n')
                udpDetailText.insert("end", "destination ip address:" + udpDetail[int(item_text[0]) - 1]["dst_ip"] + '\n')
                udpDetailText.insert("end", "source ip address:" + udpDetail[int(item_text[0]) - 1]["src_ip"] + '\n')
                udpDetailText.insert("end", "destination port:" + str(udpDetail[int(item_text[0]) - 1]["dst_port"]) + '\n')
                udpDetailText.insert("end", "source port:" + str(udpDetail[int(item_text[0]) - 1]["src_port"]) + '\n')
                udpDetailText.configure(state="disabled")

        def arp_send():
            global arp_number
            arptype = {"Request":1 , "Reply": 2}
            arp_type = {'1': "Request", '2': "Reply"}
            arpmsg = {}
            arpmsg['HARDWARE_TYPE'] = HARDWARE_TYPE.get()
            arpmsg['PROTOCOL_TYPE'] = PROTOCOL_TYPE.get()
            arpmsg['HARDWARE_LEN'] = HARDWARE_LEN.get()
            arpmsg['PROTOCOL_LEN'] = PROTOCOL_LEN.get()
            if arpType.get() == '':
                tk.messagebox.showerror(title="error", message="Please choose a type!")
                return
            arpmsg['type'] = arptype[arpType.get()]
            arpmsg['dst_mac'] =arp_dstmac.get()
            arpmsg['src_mac'] =arp_srcmac.get()
            arpmsg['src_ip'] =arp_srcip.get()
            arpmsg['dst_ip'] =arp_dstip.get()
            arp_pack = myARP(arpmsg)
            if not check_ip(arpmsg['src_ip']) or not check_ip(arpmsg['dst_ip']):
                tk.messagebox.showerror(title="error", message="Please check ip address!")
            if not Check_Mac(arpmsg['src_mac']) or not Check_Mac(arpmsg['dst_mac']):
                tk.messagebox.showerror(title="error", message="Please check mac address!")
            if arp_pack.send():
                tk.messagebox.showinfo(title="info", message="send successfully!")
                arp_number += 1
                arpDetail.append(arpmsg)
                arplog.insert('',"end", arp_number, values=(arp_number, arpmsg['src_ip'],arpmsg['src_mac'], arpmsg['dst_ip'],arpmsg['dst_mac'], arp_type[str(arpmsg['type'])]))
        def arp_show(event):
            arpDetailText.configure(state="normal")  #防止数据被修改
            arpDetailText.delete(1.0, tk.END)
            arp_type = {'1': "Request", '2':"Reply" }
            for item in arplog.selection():
                item_text = arplog.item(item, "values")
                print(item_text)
                print(arpDetail[int(item_text[0]) - 1])
                arpDetailText.insert("insert", "number:" + item_text[0] + '\n')
                arpDetailText.insert("end", "op code:" + arp_type[str(arpDetail[int(item_text[0]) - 1]["type"])] + '\n')
                arpDetailText.insert("end","destination ip address:" + arpDetail[int(item_text[0]) - 1]["dst_ip"] + '\n')
                arpDetailText.insert("end", "source ip address:" + arpDetail[int(item_text[0]) - 1]["src_ip"] + '\n')
                arpDetailText.insert("end", "destination mac address:" + str(arpDetail[int(item_text[0]) - 1]["dst_mac"]) + '\n')
                arpDetailText.insert("end", "source mac address:" + str(arpDetail[int(item_text[0]) - 1]["src_mac"]) + '\n')
                arpDetailText.configure(state="disabled")

        def icmp_send():
            global icmp_number
            #print(number)
            icmpmsg={}
            icmptype={"8":"request","0":"reply"}
            icmpmsg['data'] = (icmp_data.get()).encode()

            try:
                icmpmsg['type']=icmp_type.get()
                check=int(icmpmsg['type'])
            except:
                tk.messagebox.showerror(title="error", message="Please check type!")
                return
            try:
                icmpmsg['code'] = icmp_code.get()
                check = int(icmpmsg['code'])
                assert check <= 255
            except:
                tk.messagebox.showerror(title="error", message="Please check code!")
                return
            try:
                icmpmsg['seq']=icmp_seq.get()
                check = int(icmpmsg['code'])
            except:
                tk.messagebox.showerror(title="error", message="Please check sequence!")
                return
            try:
                icmpmsg['id']=icmp_id.get()
                check = int(icmpmsg['id'])
            except:
                tk.messagebox.showerror(title="error", message="Please check identifier!")
                return
            icmpmsg['src_ip'] = icmp_src.get()
            if not check_ip(icmpmsg['src_ip']):
                tk.messagebox.showerror(title="error", message="Please check source ip address!")
                return
            icmpmsg['dst_ip']=icmp_dst.get()
            if not check_ip(icmpmsg['dst_ip']):
                tk.messagebox.showerror(title="error", message="Please check destination ip address!")
                return
            icmp_pack= myICMP(icmpmsg)
            if icmp_pack.send():
                tk.messagebox.showinfo(title="info", message="send successfully!")
            else:
                tk.messagebox.showerror(title="error", message="reply not received")
            icmpDetail.append(icmpmsg)
            icmp_number += 1
            icmplog.insert('', icmp_number,values=(icmp_number, icmpmsg['src_ip'], icmpmsg['dst_ip'],icmptype[str(icmpmsg['type'])]))
        def icmp_show(event):
            icmpDetailText.configure(state="normal")
            icmptype = {"8": "request", "0": "reply"}
            icmpDetailText.delete(1.0,tk.END)
            for item in icmplog.selection():
                item_text = icmplog.item(item, "values")
                print(item_text)
                print(icmpDetail[int(item_text[0])-1])
                icmpDetailText.insert("insert", "number:"+item_text[0]+'\n')
                icmpDetailText.insert("end", b"data:" + icmpDetail[int(item_text[0])-1]["data"] + b'\n')
                icmpDetailText.insert("end","type:"+icmptype[str(icmpDetail[int(item_text[0])-1]["type"])]+'\n')
                icmpDetailText.insert("end", "destination ip address:" + icmpDetail[int(item_text[0])-1]["dst_ip"] + '\n')
                icmpDetailText.insert("end", "source ip address:" + icmpDetail[int(item_text[0])-1]["src_ip"] + '\n')
                icmpDetailText.insert("end", "code:" + str(icmpDetail[int(item_text[0])-1]["code"]) + '\n')
                icmpDetailText.insert("end", "sequence:" + str(icmpDetail[int(item_text[0]) - 1]["seq"]) + '\n')
                icmpDetailText.insert("end", "identifier:" + str(icmpDetail[int(item_text[0]) - 1]["id"]) + '\n')
                icmpDetailText.configure(state="disabled")
        # Change tab 切换选项卡
        def changeTag(tag):
            frame0.pack_forget()
            frame3.pack_forget()#移除原有frame，但是并没有摧毁
            frame4.pack_forget()
            frame5.pack_forget()
            frame6.pack_forget()
            frame7.pack_forget()
            if tag == 0:
                frame3.pack(fill=tk.X)#宽度随屏幕变化
            elif tag == 1:
                frame4.pack(fill=tk.X)
            elif tag == 2:
                frame5.pack(fill=tk.X)
            elif tag == 3:
                frame6.pack(fill=tk.X)
            elif tag == 4:
                frame7.pack(fill=tk.X)


        window = tk.Tk()

        window.title(self.TITLE)
        TitleStyle = tkFont.Font(family="黑体", size=20)
        # Place GUI on the center of screen
        self.ws = window.winfo_screenwidth()
        self.hs = window.winfo_screenheight()
        x = (self.ws / 2) - (self.WIDTH / 2)
        y = (self.hs / 2) - (self.HEIGHT / 2)
        window.geometry('%dx%d+%d+%d' % (self.WIDTH, self.HEIGHT, x, y))
        icmpDetail = []
        arpDetail = []
        tcpDetail = []
        udpDetail = []
        ipDetail = []

        frame0 = tk.Frame(window, height=200, bg="white") #欢迎界面
        frame2 = tk.Frame(window)#选项卡
        frame2.pack(fill=tk.Y, pady=10)
        tag = tk.IntVar()
        tagWidth = 23
        width = 10
        tk.Radiobutton(frame2, text="IP", command=lambda: changeTag(0), variable=tag, width=tagWidth,  value=0, bd=1,indicatoron=0).grid(column=0, row=1)
        tk.Radiobutton(frame2, text="TCP", command=lambda: changeTag(1), variable=tag, width=tagWidth, value=1, bd=1,indicatoron=0).grid(column=1, row=1)
        tk.Radiobutton(frame2, text="UDP", command=lambda: changeTag(2), variable=tag, width=tagWidth, value=2, bd=1,indicatoron=0).grid(column=2, row=1)
        tk.Radiobutton(frame2, text="ARP", command=lambda: changeTag(3), variable=tag, width=tagWidth, value=3, bd=1,indicatoron=0).grid(column=3, row=1)
        tk.Radiobutton(frame2, text="ICMP", command=lambda: changeTag(4), variable=tag, width=tagWidth, value=4, bd=1,indicatoron=0).grid(column=4, row=1)

        # frame3 --------我-----是------分-------割--------线-------！-----> IP
        frame3 = tk.Frame(window, height=300, bg="white")
        frame3.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame3, text="发送IP报文", font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        ipTypeSet = tk.Frame(frame3, bg="white")
        ipTypeSet.pack(side=tk.TOP, fill=tk.X)
        ipnumberSet = tk.Frame(frame3, bg="white")
        ipnumberSet.pack(side=tk.TOP, fill=tk.X)
        ipflagSet = tk.Frame(frame3, bg="white")
        ipflagSet.pack(side=tk.TOP, fill=tk.X)
        ipdataSet = tk.Frame(frame3, bg="white")
        ipdataSet.pack(side=tk.TOP, fill=tk.X)

        DF = tk.IntVar()
        MF = tk.IntVar()
        ipVersion = tk.IntVar(value=4)
        ip_id = tk.IntVar(value=1)
        ttl = tk.IntVar(value=100)
        ip_opt = tk.StringVar(value="")  # last here 12.15
        ip_srcip = tk.StringVar(value=get_host_ip())
        ip_dstip = tk.StringVar(value='182.61.200.6')
        ip_data = tk.StringVar(value='')
        tk.Button(ipdataSet, text="send", command=ip_send, bd=3).grid(row=0, column=3, padx=5)
        tk.Label(ipTypeSet, text="Source IP Address", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(ipTypeSet, textvariable=ip_srcip, width=23, bd=3, bg="white").grid(row=0, column=1, padx=5)
        tk.Label(ipTypeSet, text="Destination IP Address", bd=3).grid(row=0, column=2, padx=5)
        tk.Entry(ipTypeSet, textvariable=ip_dstip, width=23, bd=3, bg="white").grid(row=0, column=3, padx=5)
        tk.Label(ipdataSet, text="Data", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(ipdataSet, textvariable=ip_data, width=100, bd=3, bg="white").grid(row=0, column=1, padx=5)
        tk.Label(ipflagSet, text="DF", bd=3).grid(row=0, column=8, padx=5)
        tk.Entry(ipflagSet, textvariable=DF, width=2, bd=3, bg="white").grid(row=0, column=9, padx=5)
        tk.Label(ipflagSet, text="MF", bd=3).grid(row=0, column=10, padx=5)
        tk.Entry(ipflagSet, textvariable=MF, width=2, bd=3, bg="white").grid(row=0, column=11, padx=5)
        tk.Label(ipflagSet, text="Upper protocol", bd=3).grid(row=0, column=0, padx=5)
        ipupType = ttk.Combobox(ipflagSet, state='readonly',width=10)
        ipupType['value'] = ('ICMP', 'TCP','UDP')
        ipupType.grid(row=0, column=1, padx=0)
        tk.Label(ipflagSet, text="Version", bd=3).grid(row=0, column=2, padx=5)
        tk.Entry(ipflagSet, textvariable=ipVersion, width=2, bd=3, bg="white",state="disabled").grid(row=0, column=3, padx=5)
        tk.Label(ipflagSet, text="identifier", bd=3).grid(row=0, column=4, padx=5)
        tk.Entry(ipflagSet, textvariable=ip_id, width=15, bd=3, bg="white").grid(row=0, column=5, padx=5)
        tk.Label(ipTypeSet, text="Time to live", bd=3).grid(row=0, column=6, padx=5)
        tk.Entry(ipTypeSet, textvariable=ttl, width=10, bd=3, bg="white").grid(row=0, column=9, padx=5)
        tk.Label(ipflagSet, text="Options", bd=3).grid(row=0, column=6, padx=5)
        tk.Entry(ipflagSet, textvariable=ip_opt, width=15, bd=3, bg="white").grid(row=0, column=7, padx=5)

        ipInfo = tk.Frame(frame3, bg="white")
        tk.Label(ipInfo, text="IP send history", bd=3).grid(row=0, column=1, padx=5)
        tk.Label(ipInfo, text="IP package detail", bd=3).grid(row=0, column=2, padx=5)
        ipDetailText = tk.Text(ipInfo, bg="white")

        ipDetailText.grid(row=1, column=2, padx=5, sticky=tk.E)
        ipDetailText.insert("insert", "no selected packages!")
        ipDetailText.configure(state="disabled")

        ipscrolly = tk.Scrollbar(ipInfo)
        ipscrollx = tk.Scrollbar(ipInfo, orient=tk.HORIZONTAL)
        iplog = ttk.Treeview(ipInfo, show="headings", yscrollcommand=ipscrolly.set, xscrollcommand=ipscrollx.set)
        ipscrolly.grid(row=1, column=0, sticky=tk.W + tk.S + tk.N)
        ipscrolly.config(command=iplog.yview)
        ipscrollx.grid(row=2, column=1, sticky=tk.W + tk.E + tk.N)
        ipscrollx.config(command=iplog.xview)

        iplog['columns'] = ['number', 'Source ip Address',  'Destination ip Address']
        iplog.column('number', width=60)
        iplog.column('Source ip Address', width=100)
        iplog.column('Destination ip Address', width=100)
        iplog.heading('number', text='number')
        iplog.heading('Source ip Address', text='Source ip')
        iplog.heading('Destination ip Address', text='Destination ip')
        iplog.bind("<Double-1>", ip_show)
        iplog.grid(row=1, column=1)
        ipInfo.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        iplog.grid(row=1, column=1)
        frame3.pack_forget()

        # frame4 --------我-----是------分-------割--------线-------！-----> TCP
        frame4 = tk.Frame(window, height=350, bg="white")
        frame4.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame4, text="发送TCP报文", font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        tcpTypeSet = tk.Frame(frame4, bg="white")
        tcpTypeSet.pack(side=tk.TOP, fill=tk.X)
        tcpnumberSet = tk.Frame(frame4, bg="white")
        tcpnumberSet.pack(side=tk.TOP, fill=tk.X)
        tcpflagSet = tk.Frame(frame4, bg="white")
        tcpflagSet.pack(side=tk.TOP, fill=tk.X)
        tcpdataSet = tk.Frame(frame4, bg="white")
        tcpdataSet.pack(side=tk.TOP, fill=tk.X)

        CWR = tk.IntVar()
        ECE = tk.IntVar()
        URG = tk.IntVar()
        ACK = tk.IntVar()
        PSH = tk.IntVar()
        RST = tk.IntVar()
        SYN = tk.IntVar()
        FIN = tk.IntVar()
        opt = tk.StringVar()
        seq_num = tk.IntVar()
        ack_num = tk.IntVar()
        urgent_pointer = tk.IntVar()
        win_size = tk.IntVar(value=1024)  #last here 12.15
        tcp_dport = tk.IntVar(value=80)
        tcp_sport = tk.IntVar(value=8091)
        tcp_srcip = tk.StringVar(value=get_host_ip())
        tcp_dstip = tk.StringVar(value='182.61.200.6')
        tcp_data = tk.StringVar(value='')
        tk.Button(tcpdataSet, text="send", command=tcp_send, bd=3).grid(row=0, column=3, padx=5)
        tk.Label(tcpTypeSet, text="Destination Port").grid(row=0, column=0, padx=0)
        tk.Entry(tcpTypeSet, textvariable=tcp_dport, width=5, bd=3, bg="white").grid(row=0, column=1, padx=0)
        tk.Label(tcpTypeSet, text="Source Port").grid(row=0, column=2, padx=0)
        tk.Entry(tcpTypeSet, textvariable=tcp_sport, width=5, bd=3, bg="white").grid(row=0, column=3, padx=0)
        tk.Label(tcpTypeSet, text="Source IP Address", bd=3).grid(row=0, column=4, padx=5)
        tk.Entry(tcpTypeSet, textvariable=tcp_srcip, width=20, bd=3, bg="white").grid(row=0, column=5, padx=5)
        tk.Label(tcpTypeSet, text="Destination IP Address", bd=3).grid(row=0, column=6, padx=5)
        tk.Entry(tcpTypeSet, textvariable=tcp_dstip, width=20, bd=3, bg="white").grid(row=0, column=7, padx=5)
        tk.Label(tcpdataSet, text="Data", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(tcpdataSet, textvariable=tcp_data, width=100, bd=3, bg="white").grid(row=0, column=1, padx=5)
        tk.Label(tcpflagSet, text="CWR", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(tcpflagSet, textvariable=CWR, width=2, bd=3, bg="white").grid(row=0, column=1, padx=5)
        tk.Label(tcpflagSet, text="ECE", bd=3).grid(row=0, column=2, padx=5)
        tk.Entry(tcpflagSet, textvariable=ECE, width=2, bd=3, bg="white").grid(row=0, column=3, padx=5)
        tk.Label(tcpflagSet, text="URG", bd=3).grid(row=0, column=4, padx=5)
        tk.Entry(tcpflagSet, textvariable=URG, width=2, bd=3, bg="white").grid(row=0, column=5, padx=5)
        tk.Label(tcpflagSet, text="ACK", bd=3).grid(row=0, column=6, padx=5)
        tk.Entry(tcpflagSet, textvariable=ACK, width=2, bd=3, bg="white").grid(row=0, column=7, padx=5)
        tk.Label(tcpflagSet, text="PSH", bd=3).grid(row=0, column=8, padx=5)
        tk.Entry(tcpflagSet, textvariable=PSH, width=2, bd=3, bg="white").grid(row=0, column=9, padx=5)
        tk.Label(tcpflagSet, text="RST", bd=3,width=3).grid(row=0, column=10, padx=5)
        tk.Entry(tcpflagSet, textvariable=RST, width=2, bd=3, bg="white").grid(row=0, column=11, padx=5)
        tk.Label(tcpflagSet, text="SYN", bd=3).grid(row=0, column=12, padx=5)
        tk.Entry(tcpflagSet, textvariable=SYN, width=2, bd=3, bg="white").grid(row=0, column=13, padx=5)
        tk.Label(tcpflagSet, text="FIN", bd=3).grid(row=0, column=14, padx=5)
        tk.Entry(tcpflagSet, textvariable=FIN, width=2, bd=3, bg="white").grid(row=0, column=15, padx=5)
        tk.Label(tcpnumberSet, text="Window Size", bd=3).grid(row=0, column=4, padx=5)
        tk.Entry(tcpnumberSet, textvariable=win_size, width=5, bd=3, bg="white").grid(row=0, column=5, padx=5)
        tk.Label(tcpflagSet, text="Urgent Pointer", bd=3).grid(row=0, column=16, padx=5)
        tk.Entry(tcpflagSet, textvariable=urgent_pointer, width=7, bd=3, bg="white").grid(row=0, column=17, padx=5)
        tk.Label(tcpnumberSet, text="Sequence Number", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(tcpnumberSet, textvariable=seq_num, width=10, bd=3, bg="white").grid(row=0, column=1, padx=5)
        tk.Label(tcpnumberSet, text="Acknowledge number", bd=3).grid(row=0, column=2, padx=5)
        tk.Entry(tcpnumberSet, textvariable=ack_num, width=10, bd=3, bg="white").grid(row=0, column=3, padx=5)
        tk.Label(tcpnumberSet, text="Options", bd=3).grid(row=0, column=18, padx=5)
        tk.Entry(tcpnumberSet, textvariable=opt, width=10, bd=3, bg="white").grid(row=0, column=19, padx=5)

        tcpInfo = tk.Frame(frame4, bg="white")
        tk.Label(tcpInfo, text="TCP send history", bd=3).grid(row=0, column=1, padx=5)
        tk.Label(tcpInfo, text="TCP package detail", bd=3).grid(row=0, column=2, padx=5)
        tcpDetailText = tk.Text(tcpInfo, bg="white")

        tcpDetailText.grid(row=1, column=2, padx=5, sticky = tk.E)
        tcpDetailText.insert("insert", "no selected packages!")
        tcpDetailText.configure(state="disabled")

        tcpscrolly = tk.Scrollbar(tcpInfo)
        tcpscrollx = tk.Scrollbar(tcpInfo, orient=tk.HORIZONTAL)
        tcplog = ttk.Treeview(tcpInfo, show="headings", yscrollcommand=tcpscrolly.set, xscrollcommand=tcpscrollx.set)
        tcpscrolly.grid(row=1, column=0, sticky=tk.W + tk.S + tk.N)
        tcpscrolly.config(command=tcplog.yview)
        tcpscrollx.grid(row=2, column=1, sticky=tk.W + tk.E + tk.N)
        tcpscrollx.config(command=tcplog.xview)

        tcplog['columns'] = ['number', 'Source ip Address', 'Source Port', 'Destination ip Address','Destination Port']
        tcplog.column('number', width=60)
        tcplog.column('Source ip Address', width=100)
        tcplog.column('Destination ip Address', width=100)
        tcplog.column('Source Port', width=100)
        tcplog.column('Destination Port', width=100)
        tcplog.heading('number', text='number')
        tcplog.heading('Source ip Address', text='Source ip')
        tcplog.heading('Destination ip Address', text='Destination ip')
        tcplog.heading('Source Port', text='Source Port')
        tcplog.heading('Destination Port', text='Destination Port')
        tcplog.bind("<Double-1>", tcp_show)
        tcplog.grid(row=1, column=1)
        tcpInfo.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        tcplog.grid(row=1, column=1)

        frame4.pack_forget()

        # frame5 --------我-----是------分-------割--------线-------！-----> UDP
        frame5 = tk.Frame(window, height=350, bg="white")
        frame5.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame5, text="发送UDP报文", font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        udpTypeSet = tk.Frame(frame5, bg="white")
        udpTypeSet.pack(side=tk.TOP, fill=tk.X)
        udpdataSet = tk.Frame(frame5, bg="white")
        udpdataSet.pack(side=tk.TOP, fill=tk.X)
        udp_dport = tk.IntVar(value=8001)
        udp_sport = tk.IntVar(value=8002)
        udp_srcip = tk.StringVar(value=get_host_ip())
        udp_dstip = tk.StringVar(value='8.8.8.8')
        udp_data = tk.StringVar(value='')
        tk.Button(udpdataSet, text="send", command=udp_send, bd=3).grid(row=0, column=3, padx=5)
        tk.Label(udpTypeSet, text="Destination Port").grid(row=0, column=0, padx=0)
        tk.Entry(udpTypeSet, textvariable=udp_dport, width=5, bd=3, bg="white").grid(row=0, column=1, padx=0)
        tk.Label(udpTypeSet, text="Source Port").grid(row=0, column=2, padx=0)
        tk.Entry(udpTypeSet, textvariable=udp_sport, width=5, bd=3, bg="white").grid(row=0, column=3, padx=0)
        tk.Label(udpTypeSet, text="Source IP Address",bd=3).grid(row=0, column=4, padx=5)
        tk.Entry(udpTypeSet, textvariable=udp_srcip, width=20, bd=3, bg="white").grid(row=0, column=5, padx=5)
        tk.Label(udpTypeSet, text="Destination IP Address", bd=3).grid(row=0, column=6, padx=5)
        tk.Entry(udpTypeSet, textvariable=udp_dstip, width=20, bd=3, bg="white").grid(row=0, column=7, padx=5)
        tk.Label(udpdataSet, text="Data", bd=3).grid(row=0, column=0, padx=5)
        tk.Entry(udpdataSet, textvariable=udp_data, width=100, bd=3, bg="white").grid(row=0, column=1, padx=5)

        udpInfo = tk.Frame(frame5, bg="white")
        tk.Label(udpInfo, text="UDP send history", bd=3).grid(row=0, column=1, padx=5)
        tk.Label(udpInfo, text="UDP package detail", bd=3).grid(row=0, column=2, padx=5)
        udpDetailText = tk.Text(udpInfo, bg="white")

        udpDetailText.grid(row=1, column=2, padx=5)
        udpDetailText.insert("insert", "no selected packages!")
        udpDetailText.configure(state="disabled")

        udpscrolly = tk.Scrollbar(udpInfo)
        udpscrollx = tk.Scrollbar(udpInfo, orient=tk.HORIZONTAL)
        udplog = ttk.Treeview(udpInfo, show="headings", yscrollcommand=udpscrolly.set, xscrollcommand=udpscrollx.set)
        udpscrolly.grid(row=1, column=0, sticky=tk.W + tk.S + tk.N)
        udpscrolly.config(command=udplog.yview)
        udpscrollx.grid(row=2, column=1, sticky=tk.W + tk.E + tk.N)
        udpscrollx.config(command=udplog.xview)

        udplog['columns'] = ['number', 'Source ip Address', 'Source Port', 'Destination ip Address',
                             'Destination Port']
        udplog.column('number', width=60)

        udplog.column('Source ip Address', width=100)
        udplog.column('Destination ip Address', width=100)
        udplog.column('Source Port', width=100)
        udplog.column('Destination Port', width=100)
        udplog.heading('number', text='number')
        udplog.heading('Source ip Address', text='Source ip')
        udplog.heading('Destination ip Address', text='Destination ip')
        udplog.heading('Source Port', text='Source Port')
        udplog.heading('Destination Port', text='Destination Port')
        udplog.bind("<Double-1>", udp_show)
        udplog.grid(row=1, column=1)
        udpInfo.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        udplog.grid(row=1, column=1)


        frame5.pack_forget()


        # frame6 --------我-----是------分-------割--------线-------！-----> ARP
        frame6 = tk.Frame(window, height=300, bg="white")
        frame6.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame6, text="发送ARP报文", font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        arpTypeSet = tk.Frame(frame6, bg="white")
        arpTypeSet.pack(side=tk.TOP,fill=tk.X)
        arp_dstmac = tk.StringVar(value = '00:00:00:00:00:00')
        arp_srcmac = tk.StringVar(value = get_mac())
        arp_srcip = tk.StringVar(value = get_host_ip())
        arp_dstip = tk.StringVar(value = '8.8.8.8')
        tk.Button(arpTypeSet, text="send", command=arp_send, bd=3).grid(row=1, column=0, padx=5)
        tk.Label(arpTypeSet, text="Type").grid(row=0, column=0,  padx=0)
        arpType=ttk.Combobox(arpTypeSet, state='active')
        arpType['value'] = ('Reply', 'Request')
        arpType.configure(state="readonly")
        arpType.grid(row=0, column=1,  padx=0)
        '''tk.Radiobutton(arpTypeSet, text="Request", variable=arp_type, value=8, bd=1,
                       indicatoron=1, width=width, padx=10).grid(row=0, column=1, padx=0)
        tk.Radiobutton(arpTypeSet, text="Reply", variable=arp_type, value=0, bd=1,
                       indicatoron=1, width=width).grid(row=0, column=2, padx=0)'''
        tk.Label(arpTypeSet, text="Source MAC Address").grid(row=0, column=3, padx=0)
        tk.Entry(arpTypeSet, textvariable=arp_srcmac, width=20, bd=3, bg="white").grid(row=0, column=4, padx=0)
        tk.Label(arpTypeSet, text="Source IP Address",bd=3).grid(row=0, column=5, padx=5)
        tk.Entry(arpTypeSet, textvariable=arp_srcip, width=20, bd=3, bg="white").grid(row=0, column=6, padx=5)
        tk.Label(arpTypeSet, text="Destination MAC Address").grid(row=1, column=3, padx=0)
        tk.Entry(arpTypeSet, textvariable=arp_dstmac, width=20, bd=3, bg="white").grid(row=1, column=4, padx=0)
        tk.Label(arpTypeSet, text="Destination IP Address", bd=3).grid(row=1, column=5, padx=5)
        tk.Entry(arpTypeSet, textvariable=arp_dstip, width=20, bd=3, bg="white").grid(row=1, column=6, padx=5)
        HARDWARE_TYPE = tk.StringVar()
        HARDWARE_LEN = tk.StringVar()
        PROTOCOL_TYPE = tk.StringVar()
        PROTOCOL_LEN = tk.StringVar()
        HARDWARE_TYPE.set("0x0001")
        HARDWARE_LEN.set("0x0006")
        PROTOCOL_TYPE.set("0x0800")
        PROTOCOL_LEN.set("0x0004")


        UselessEntry = tk.Frame(frame6)
        UselessEntry.pack(side=tk.TOP, fill=tk.X)
        tk.Label(UselessEntry, text="HARDWARE_TYPE", bd=3).grid(row=2, column=0, padx=5)
        tk.Entry(UselessEntry, textvariable=HARDWARE_TYPE, width=10, bd=3, bg="white", state='disabled').grid(row=2, column=1, padx=5)
        tk.Label(UselessEntry, text="HARDWARE_LEN", bd=3).grid(row=2, column=3, padx=5)
        tk.Entry(UselessEntry, textvariable=HARDWARE_LEN, width=10, bd=3, bg="white", state='disabled').grid(row=2, column=4, padx=5)
        tk.Label(UselessEntry, text="PROTOCOL_TYPE", bd=3).grid(row=2, column=5, padx=5)
        tk.Entry(UselessEntry, textvariable=PROTOCOL_TYPE, width=10, bd=3, bg="white", state='disabled').grid(row=2, column=6, padx=5)
        tk.Label(UselessEntry, text="PROTOCOL_LEN", bd=3).grid(row=2, column=7, padx=5)
        tk.Entry(UselessEntry, textvariable=PROTOCOL_LEN, width=10, bd=3, bg="white", state='disabled').grid(row=2, column=8, padx=5)
        arpInfo1 = tk.Frame(frame6, bg="white", width=200)

        arpInfo = tk.Frame(arpInfo1, bg="white")
        tk.Label(arpInfo, text="ARP send history", bd=3).grid(row=0, column=1, padx=5)
        tk.Label(arpInfo, text="ARP package detail", bd=3).grid(row=0, column=2, padx=5)
        arpDetailText = tk.Text(arpInfo, bg="white")

        arpDetailText.grid(row=1, column=2, padx=5)
        arpDetailText.insert("insert", "no selected packages!")
        arpDetailText.configure(state="disabled")

        arpscrolly = tk.Scrollbar(arpInfo)
        arpscrollx = tk.Scrollbar(arpInfo,orient=tk.HORIZONTAL)
        arplog = ttk.Treeview(arpInfo, show="headings", yscrollcommand=arpscrolly.set,xscrollcommand=arpscrollx.set)
        arpscrolly.grid(row=1, column=0, sticky=tk.W + tk.N + tk.N)
        arpscrolly.config(command=arplog.yview)
        arpscrollx.grid(row=2, column=1, sticky=tk.W + tk.E+ tk.N)
        arpscrollx.config(command=arplog.xview)

        arplog['columns'] = ['number', 'Source ip Address','Source mac Address','Destination ip Address','Destination mac Address' , 'Type']
        arplog.column('number', width=60)

        arplog.column('Source ip Address', width=80)
        arplog.column('Destination ip Address', width=100)
        arplog.column('Source mac Address', width=80)
        arplog.column('Destination mac Address', width=100)
        arplog.column('Type', width=60)
        arplog.heading('number', text='number')
        arplog.heading('Source ip Address', text='Source ip')
        arplog.heading('Destination ip Address', text='Destination ip')
        arplog.heading('Source mac Address', text='Source mac')
        arplog.heading('Destination mac Address', text='Destination mac')
        arplog.heading('Type', text='Type')
        arplog.bind("<Double-1>", arp_show)
        arplog.grid(row=1, column=1)
        arpInfo1.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        arpInfo.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        arplog.grid(row=1, column=1)


        frame6.pack_forget()
        # frame7 --------我-----是------分-------割--------线-------！-----> ICMP
        frame7 = tk.Frame(window, height=300, bg="white")
        frame7.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame7, text="发送ICMP报文",font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        icmpTypeSet = tk.Frame(frame7, bg="white")
        icmp_type=tk.IntVar(value=8)
        icmp_code=tk.IntVar()
        icmp_id = tk.IntVar(value=1)
        icmp_seq = tk.IntVar()
        icmp_data = tk.StringVar(value='')
        icmp_src = tk.StringVar(value=get_host_ip())
        icmp_dst = tk.StringVar(value='8.8.8.8')
        tk.Label(icmpTypeSet, text="Type").grid(row=0, column=0,  padx=0)
        tk.Radiobutton(icmpTypeSet, text="Request", variable=icmp_type, value=8, bd=1,
                       indicatoron=1, width=width, padx=10).grid(row=0, column=1, padx=0)
        tk.Radiobutton(icmpTypeSet, text="Reply", variable=icmp_type, value=0, bd=1,
                       indicatoron=1, width=width).grid(row=0, column=2, padx=0)
        tk.Label(icmpTypeSet, text="Code").grid(row=0, column=3, padx=0)
        tk.Entry(icmpTypeSet, textvariable=icmp_code, width=20, bd=3, bg="white").grid(row=0, column=4, padx=0)
        tk.Label(icmpTypeSet, text="Identifier",bd=3).grid(row=0, column=5, padx=5)
        tk.Entry(icmpTypeSet, textvariable=icmp_id, width=20, bd=3, bg="white").grid(row=0, column=6, padx=5)
        tk.Label(icmpTypeSet, text="Sequence",bd=3).grid(row=0, column=7, padx=5)
        tk.Entry(icmpTypeSet, textvariable=icmp_seq, width=20, bd=3, bg="white").grid(row=0, column=8, padx=5)
        icmpipSet = tk.Frame(frame7, bg="white")
        tk.Label(icmpipSet, text="Source IP address", bd=3).grid(row=1, column=0, padx=5)
        tk.Entry(icmpipSet, textvariable=icmp_src, width=30, bd=3, bg="white").grid(row=1, column=1, padx=5)
        tk.Label(icmpipSet, text="Destination IP address", bd=3).grid(row=1, column=2, padx=5)
        tk.Entry(icmpipSet, textvariable=icmp_dst, width=30, bd=3, bg="white").grid(row=1, column=3, padx=5)
        tk.Label(icmpipSet, text="Source IP address", bd=3).grid(row=1, column=0, padx=5)
        tk.Button(icmpipSet,text="send",command=icmp_send, bd = 3).grid(row=2, column=2, padx=5)
        tk.Label(icmpipSet, text="Data", bd=3).grid(row=2, column=0, padx=5)
        tk.Entry(icmpipSet, textvariable=icmp_data, width=30, bd=3, bg="white").grid(row=2, column=1, padx=5)


        icmpInfo = tk.Frame(frame7, bg="white")

        '''icmpLog = tk.Frame(icmpInfo, bg="white")
        icmpDetail = tk.Frame(icmpInfo, bg="white")
        icmpLog.grid(row=0,column=0)
        icmpDetail.grid(row=0, column=0)'''
        icmpInfo.pack(side=tk.BOTTOM, fill=tk.Y, expand=tk.YES, anchor=tk.SW)
        icmpTypeSet.pack(side=tk.TOP, anchor=tk.W)
        icmpipSet.pack(side=tk.LEFT, anchor=tk.W, fill=tk.X)
        tk.Label(icmpInfo, text="ICMP send history", bd=3).grid(row=0, column=1, padx=5)
        tk.Label(icmpInfo, text="ICMP package detail", bd=3).grid(row=0, column=2, padx=5)
        icmpDetailText=tk.Text(icmpInfo, bg="white")
        icmpDetailText.grid(row=1, column=2, padx=5)
        icmpDetailText.insert("insert", "no selected packages!")
        icmpDetailText.configure(state="disabled")
        icmpscroll = tk.Scrollbar(icmpInfo)
        icmplog=ttk.Treeview(icmpInfo,show="headings", yscrollcommand=icmpscroll.set,)
        icmplog['columns'] = ['number','Source ip Address', 'Destination ip Address', 'Type']
        icmplog.column('number', width=60)

        icmplog.column('Source ip Address', width=150)
        icmplog.column('Destination ip Address', width=150)
        icmplog.column('Type', width=90)
        icmplog.heading('number', text='number')
        icmplog.heading('Source ip Address', text='Source ip Address')
        icmplog.heading('Destination ip Address', text='Destination ip Address')
        icmplog.heading('Type', text='Type')
        icmplog.bind("<Double-1>", icmp_show)
        icmplog.grid(row=1, column=1)

        icmpscroll.grid(row=1, column=0, sticky=tk.W+tk.N+tk.S)
        icmpscroll.config(command=icmplog.yview)
        frame7.pack_forget()


        def go_homepage():
            frame3.pack_forget()
            frame4.pack_forget()
            frame5.pack_forget()
            frame6.pack_forget()
            frame7.pack_forget()
            frame0.pack()

        def open_repo():
            webbrowser.open("https://github.com/Vanadylxu/SJTU-2020-IS301-MySender.git", new=0, autoraise=True)

        def clear_log():
            arpDetailText.delete(1.0, tk.END)
            icmpDetailText.delete(1.0, tk.END)
            items = icmplog.get_children()
            [icmplog.delete(item) for item in items]
            items = arplog.get_children()
            [arplog.delete(item) for item in items]

        frame0.pack()
        tk.Label(frame0,text="Welcome!",bg="white",font=TitleStyle).pack()
        text=tk.Text(frame0,bg="white")
        text.pack()
        text.insert("insert", "Welcome to my_sender,you can select a tab you like to send packages. \n")
        text.insert("end", "Five kinds of package supported: \nIP\nTCP\nUDP\nARP\nICMP\n")
        text.insert("end", "If you want to examine detail of log,please DOUBLE CLICK on the row.\n")
        text.insert("end", "All rights reserved by VanadylXu. ")
        menubar = tk.Menu(window)

        # 第6步，创建一个File菜单项（默认不下拉，下拉内容包括New，Open，Save，Exit功能项）
        filemenu = tk.Menu(menubar, tearoff=0)
        # 将上面定义的空菜单命名为File，放在菜单栏中，就是装入那个容器中
        menubar.add_cascade(label='File', menu=filemenu)

        # 在File中加入New、Open、Save等小菜单，即我们平时看到的下拉菜单，每一个小菜单对应命令操作。
        filemenu.add_command(label='Open Repo', command=open_repo)
        filemenu.add_command(label='Clear All logs', command=clear_log)
        filemenu.add_command(label='Go Homepage', command=go_homepage)
        filemenu.add_separator()  # 添加一条分隔线
        filemenu.add_command(label='Exit', command=window.quit)  # 用tkinter里面自带的quit()函数

        window.config(menu=menubar)



        window.mainloop()

if __name__ == "__main__":
    tbm = Window()
    tbm.initialGUI()