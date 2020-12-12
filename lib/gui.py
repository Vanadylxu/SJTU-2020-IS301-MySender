import tkinter as tk





if __name__ == '__main__':#GUI学习&测试
    # 创建窗口
    window = tk.Tk()
    window.title('Mywindow')  # 窗口的标题
    window.geometry('500x500')  # 窗口的大小
    # 定义一个lable
    var = tk.StringVar()  # 定义一个字符串变量
    l = tk.Label(window,
                 textvariable=var,  # 标签的文字
                 bg='green',  # 标签背景颜色
                 font=('Arial', 12),  # 字体和字体大小
                 width=15, height=2  # 标签长宽
                 )
    l.pack()  # 固定窗口位置
    # 定义一个全局变量，来表明字符显示与不显示
    on_hit = False
    # 按钮的函数
    def hit_me():
        global on_hit  # 声明全局变量
        if on_hit == False:
            on_hit = True
            var.set('正面!')
        else:
            on_hit = False
            var.set('反面!')

    e = tk.Entry(window, show=None)  # 如果是输入密码，可以写show='*'
    e.pack()
    # 定义按钮功能
    def insert_point():
        var = e.get()
        t.insert('insert', var)
    def insert_end():
        var = e.get()
        t.insert('end', var)  # 这里还可以定义字符串插入的具体位置，比如t.insert('1.1',var)，表示插入到第一行第一列


    # 定义2个按钮
    b1 = tk.Button(window,text="insert point",width=15,height=2,command=insert_point)
    b1.pack()
    b2 = tk.Button(window,text="insert end",command=insert_end)
    b2.pack()
    #定义一个文本框
    t=tk.Text(window,height=2)
    t.pack()
    # 显示出来
    # 按钮
    b = tk.Button(window, text='点我', width=15, height=2, command=hit_me)  # 点击按钮执行一个名为“hit_me”的函数
    b.pack()

    window.mainloop()