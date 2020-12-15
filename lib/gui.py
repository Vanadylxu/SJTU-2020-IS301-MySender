import tkinter as tk
import tkinter.font as tkFont
from tkinter import ttk
import tkinter.messagebox
import binascii
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
        self.WIDTH = 1000
        self.HEIGHT = 600
        self.parseDic = {}

        # Initial GUI
    def initialGUI(self):
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

        # Change type
        def changeType(tag): #frame3专用的小tab
            clockSet.pack_forget()
            resetSet.pack_forget()
            customSet.pack_forget()
            if tag == 0:
                clockSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES, pady=5, padx=10)
            elif tag == 1:
                resetSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES, pady=5, padx=10)
            elif tag == 2:
                customSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES, pady=5, padx=10)

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


        frame0 = tk.Frame(window, height=200, bg="white")


        # Tag: 0 --> input; 1 --> output; 2 --> other
        frame2 = tk.Frame(window)
        frame2.pack(fill=tk.Y, pady=10)
        tag = tk.IntVar()
        tagWidth = 23
        tk.Radiobutton(frame2, text="IP", command=lambda: changeTag(0), variable=tag, width=tagWidth,  value=0, bd=1,indicatoron=0).grid(column=0, row=1)
        tk.Radiobutton(frame2, text="TCP", command=lambda: changeTag(1), variable=tag, width=tagWidth, value=1, bd=1,indicatoron=0).grid(column=1, row=1)
        tk.Radiobutton(frame2, text="UDP", command=lambda: changeTag(2), variable=tag, width=tagWidth, value=2, bd=1,indicatoron=0).grid(column=2, row=1)
        tk.Radiobutton(frame2, text="ARP", command=lambda: changeTag(3), variable=tag, width=tagWidth, value=3, bd=1,indicatoron=0).grid(column=3, row=1)
        tk.Radiobutton(frame2, text="ICMP", command=lambda: changeTag(4), variable=tag, width=tagWidth, value=4, bd=1,indicatoron=0).grid(column=4, row=1)



        # frame3 --> IP
        # Signal info
        frame3 = tk.Frame(window, height=300, bg="")
        frame3.pack(side=tk.TOP, fill=tk.X)
        tk.Label(frame3, text="发送IP报文", font=TitleStyle).pack(side=tk.TOP, anchor=tk.N)
        scroll = tk.Scrollbar(frame3)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.inputBox = tk.Listbox(frame3, bd=1, selectmode=tk.SINGLE, yscrollcommand=scroll.set, height=8)
        self.inputBox.pack(side=tk.TOP, anchor=tk.NW, fill=tk.X, expand=tk.YES)
        scroll.config(command=self.inputBox.yview)

        width = 10
        frameInputSet = tk.Frame(frame3, bg="white")
        frameInputSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES)
        tk.Label(frameInputSet, text="  Input Setting").grid(row=0, column=0, pady=5)
        tk.Label(frameInputSet, text="  Signal Type", width=width).grid(row=1, column=0)
        # Tpye: 0 --> clock; 1 --> reset; 2 --> custom
        type = tk.IntVar()
        tk.Radiobutton(frameInputSet, text="Clock", variable=type, value=0, command=lambda:changeType(0), bd=1, indicatoron=0, width=width).grid(row=1, column=1, padx=10)
        tk.Radiobutton(frameInputSet, text="Reset", variable=type, value=1, command=lambda:changeType(1), bd=1, indicatoron=0, width=width).grid(row=1, column=2, padx=10)
        tk.Radiobutton(frameInputSet, text="Custom", variable=type, value=2, command=lambda:changeType(2), bd=1, indicatoron=0, width=width).grid(row=1, column=3, padx=10)
        # Clock setting
        initalValue = tk.StringVar()
        initalValue.set("1'b0")
        cycle = tk.StringVar()
        converse = tk.StringVar()

        clockSet = tk.Frame(frame3, bg="white")
        #clockSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES, pady=5, padx=10)
        tk.Label(clockSet, text="Initial Value").grid(row=0, column=0, pady=5)
        tk.Radiobutton(clockSet, text="1'b0", variable=initalValue, value="1'b0").grid(row=0, column=1, padx=5)
        tk.Radiobutton(clockSet, text="1'b1", variable=initalValue, value="1'b1").grid(row=0, column=2, padx=5)
        tk.Label(clockSet, text="", width=10).grid(row=0, column=3)
        tk.Label(clockSet, text="Cycle").grid(row=0, column=4, pady=5, padx=10)
        tk.Entry(clockSet, textvariable=cycle, width=10, bd=2, bg="white").grid(row=0, column=5)
        # Reset setting
        resetSet = tk.Frame(frame3, bg="white")
        tk.Label(resetSet, text="Initial Value").grid(row=0, column=0, pady=5)
        tk.Radiobutton(resetSet, text="1'b0", variable=initalValue, value="1'b0").grid(row=0, column=1, padx=5)
        tk.Radiobutton(resetSet, text="1'b1", variable=initalValue, value="1'b1").grid(row=0, column=2, padx=5)
        tk.Label(resetSet, text="", width=10).grid(row=0, column=3)
        tk.Label(resetSet, text="Converse").grid(row=0, column=4, pady=5, padx=10)
        tk.Entry(resetSet, textvariable=converse, width=10, bd=2, bg="white").grid(row=0, column=5)
        # Custom setting
        defaultValue = tk.IntVar()
        radixValue = tk.IntVar()
        radixValue.set(0)
        customSet = tk.Frame(frame3, bg="white")
        customSet.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES, pady=5, padx=10)
        # Radix 0 --> b, 1 --> o, 2 --> d, 3 --> h
        tk.Label(customSet, text="Radix").grid(row=0, column=0, pady=5, padx=1)
        tk.Radiobutton(customSet, text="Binary", variable=radixValue, value=0).grid(row=0, column=1)
        tk.Radiobutton(customSet, text="Octal", variable=radixValue, value=1).grid(row=0, column=2)
        tk.Radiobutton(customSet, text="Decimal", variable=radixValue, value=2).grid(row=0, column=3)
        tk.Radiobutton(customSet, text="Hexadecimal", variable=radixValue, value=3).grid(row=0, column=4)
        # Initial value
        tk.Label(customSet, text="Default Value").grid(row=1, column=0, pady=5, padx=10)
        tk.Radiobutton(customSet, text="default 0", variable=defaultValue, value=0).grid(row=1, column=1, padx=5)
        tk.Radiobutton(customSet, text="default 1", variable=defaultValue, value=1).grid(row=1, column=2, padx=5)
        tk.Label(customSet, text="Initial Value").grid(row=1, column=3, pady=5, padx=5)
        tk.Entry(customSet, textvariable=initalValue, width=12, bd=2, bg="white", justify=tk.RIGHT).grid(row=1, column=4)
        tk.Button(customSet, text="test", command=lambda :print(initalValue.get())).grid()
        frame3.pack_forget()
        # frame4 --> TCP
        frame4 = tk.Frame(window, height=350, bg="blue")
        tk.Label(frame4, text=" Bit         Output").pack(anchor=tk.NW)
        scroll2 = tk.Scrollbar(frame4)
        scroll2.pack(side=tk.RIGHT, fill=tk.Y)
        self.outputBox = tk.Listbox(frame4, bd=1, selectmode=tk.SINGLE, yscrollcommand=scroll2.set, height=8, width=65)
        self.outputBox.pack(side=tk.LEFT)
        scroll2.config(command=self.outputBox.yview)
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
        tk.Label(udpTypeSet, text="Soucrce Port").grid(row=0, column=2, padx=0)
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