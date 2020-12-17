
import  lib.gui
import ctypes
import sys
if ctypes.windll.shell32.IsUserAnAdmin() == 0:
    print('Sorry! You should run this with administrative privileges.')
    sys.exit()
mywindow=lib.gui.Window()
mywindow.initialGUI()

